from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import get_password_validators, validate_password as validate_pass
from rest_framework import serializers
from rest_framework.authtoken.models import Token

from Bugs.models import Bug, Comment
from bug import settings


class UserSerializer(serializers.ModelSerializer):
    """
        This serializer is used to return user details
    """
    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "username", "email")


class CommentSerializer(serializers.ModelSerializer):
    """
        This serializer is used to create comments
    """
    author = serializers.CharField(source="author.username", read_only=True)

    class Meta:
        model = Comment
        fields = "__all__"

    def validate(self, initial_data):
        initial_data['author'] = self.context.get('user')
        check = Comment.objects.filter(title=initial_data['title'], bug=initial_data['bug'], author=initial_data['author'])
        check = check.exclude(id=self.instance.id) if self.instance else check
        if check.exists():
            raise serializers.ValidationError(detail="You already made a comment with this title")
        return initial_data


class CommentListSerializer(CommentSerializer):
    """
        This serializer is used to display a comment
    """
    bug = serializers.CharField(source="bug.title")


class BugSerializer(serializers.ModelSerializer):
    """
        This serializer is used to create a bug
    """
    resolved = serializers.BooleanField(read_only=True)

    class Meta:
        model = Bug
        exclude = ('assigner',)

    def validate_title(self, value):
        check = Bug.objects.filter(title=value)
        check = check.exclude(id=self.instance.id) if self.instance else check
        if check.exists():
            raise serializers.ValidationError(detail="A bug with this title already exists")
        return value

    def validate(self, initial_data):
        data_length = len(initial_data)
        user = self.context.get('user')
        if not self.instance:
            initial_data['assigner'] = self.context.get('assigner')
            # this ensures that the assigner doesn't assign the bug to himself
            if initial_data['assigner'] == initial_data.get('assignee'):
                raise serializers.ValidationError(detail="You cannot assign a bug to yourself")
        if self.instance:
            # if user is not an assigner or an assignee, the user cannot update a bug
            if user not in [self.instance.assigner, self.instance.assignee]:
                raise serializers.ValidationError(detail="this is not a valid action")
            # This ensures that an assignee can ONLY resolve a bug
            assignee_action = 'resolved' in initial_data and data_length == 1 and user == self.instance.assignee
            """
                This checks if a user trying to do more than resolve a bug and is not an assigner 
                and throws and error if true
            """
            if not (assignee_action or user == self.instance.assigner):
                raise serializers.ValidationError(detail="you are only permitted to resolve a bug")
            # this ensures that an assigner doesn't assign a bug to himself
            if user == initial_data.get('assignee'):
                raise serializers.ValidationError(detail="You cannot assign a bug to yourself")
        return initial_data


class UpdateBugSerializer(BugSerializer):
    """
        This serializer is used to update a bug
    """
    resolved = serializers.BooleanField(required=False)


class BugDetailSerializer(serializers.ModelSerializer):
    """
        This serializer is used to display bug details
    """
    assigner = UserSerializer(read_only=True)
    assignee = UserSerializer(read_only=True)
    comments = serializers.ListSerializer(child=CommentListSerializer(), read_only=True)

    class Meta:
        model = Bug
        fields = '__all__'

    def get_comments(self, obj):
        return CommentListSerializer(obj.comments, many=True).data


class BugListSerializer(BugDetailSerializer):
    """
        This serializer is used to display list of bugs
    """
    assignee = serializers.CharField(read_only=True)
    assigner = serializers.CharField(read_only=True)

    class Meta:
        model = Bug
        fields = ('id', 'title', 'resolved', 'assigner', 'assignee')


class SignupSerializer(serializers.ModelSerializer):
    """
        This serializer is used to create a new user account
    """
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("first_name", "last_name", "username", "email", "password")

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(detail="A user already exists with this email address")
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError(detail="A user already exists with this username")
        return value

    def validate_password(self, value):
        validate_pass(
            password=value,
            user=None,
            password_validators=get_password_validators(settings.AUTH_PASSWORD_VALIDATORS)
        )
        return value

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return UserSerializer(user).data


class SigninSerializer(serializers.ModelSerializer):
    """
        This serializer is used to sign in to an account
    """
    class Meta:
        model = User
        fields = ("email", "password")

    def validate(self, initial_data):
        user = User.objects.filter(email=initial_data.pop('email')).first()
        # this checks if a user with this email exists
        if not user:
            raise serializers.ValidationError(detail="You dont have an account with us")
        # this checks if the password tallies with the user account
        if user and not user.check_password(initial_data.pop('password')):
            raise serializers.ValidationError(detail="Invalid login credentials")
        if not user.is_active:
            raise serializers.ValidationError(detail="You cannot be logged in")
        initial_data['user'] = user
        return initial_data

    def create(self, validated_data):
        login(self.context.get('request'), user=validated_data['user'])
        data = UserSerializer(validated_data['user']).data
        # this creates an auth token for the user to login with
        data['token'] = Token.objects.get_or_create(user=validated_data.pop('user'))[0].key
        return data


class SignOutSerializer(serializers.Serializer):
    """
        This signs a user out of the system
    """

    def create(self, validated_data):
        request = self.context.pop('request')
        """
        this deletes the token for the user out of the system to prevent login 
        with any token belonging to that user   
        """
        Token.objects.filter(user=request.user).delete()
        logout(request=request)
        return request.user
