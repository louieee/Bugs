from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from Bugs import serializers
from Bugs.models import Bug, Comment

# Create your views here.
resolved_query = openapi.Parameter(name="resolved", in_=openapi.IN_QUERY, type=openapi.TYPE_BOOLEAN)
assigner_query = openapi.Parameter(name="assigner", in_=openapi.IN_QUERY, type=openapi.TYPE_NUMBER)
assignee_query = openapi.Parameter(name="assignee", in_=openapi.IN_QUERY, type=openapi.TYPE_NUMBER)


class BugAPI(ModelViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.BugDetailSerializer
    queryset = Bug.objects.all().order_by('-updated_at')
    http_method_names = ('get', 'patch', 'post', 'delete')

    def filter_queryset(self, queryset):
        """
        This enables one to filter the bugs using the following queries:
            - resolved (true or false): this checks for resolved bugs or unresolved bugs
            - assigner (user id): this filters bugs whose assigner's user id is what was passed here
            - assignee (user id): this filters bugs whose assignee's user id is what was passed here
        :param queryset:
        :return: the filtered bugs queryset
        """
        resolved = self.request.query_params.get('resolved', None)
        assigner = self.request.query_params.get('assigner', None)
        assignee = self.request.query_params.get('assignee', None)
        resolved = True if resolved == 'true' else False if resolved else None
        if resolved is not None:
            queryset = queryset.filter(resolved=resolved)
        if assignee:
            queryset = queryset.filter(assignee_id=assignee)
        if assigner:
            queryset = queryset.filter(assigner_id=assigner)
        return queryset

    @swagger_auto_schema(
        operation_summary="retrieves a bug",
        operation_id='bug_get')
    def retrieve(self, request, *args, **kwargs):
        return super(BugAPI, self).retrieve(request, *args, **kwargs)

    @swagger_auto_schema(
        manual_parameters=[resolved_query, assigner_query, assignee_query],
        operation_summary="retrieves a list of bugs",
        operation_id='bug_list', responses={200: serializers.BugListSerializer(many=True)})
    def list(self, request, *args, **kwargs):
        self.serializer_class = serializers.BugListSerializer
        return super(BugAPI, self).list(request, *args, **kwargs)

    @swagger_auto_schema(
        request_body=serializers.BugSerializer,
        operation_summary="creates a bug",
        operation_id='bug_create',
        responses={201: serializers.BugDetailSerializer()}
    )
    def create(self, request, *args, **kwargs):
        serializer = serializers.BugSerializer(data=request.data, context={"assigner": request.user})
        serializer.is_valid(raise_exception=True)
        bug = serializer.save()
        return Response(data=serializers.BugDetailSerializer(bug).data, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        request_body=serializers.UpdateBugSerializer,
        operation_description="""
            Actions that can be performed with this endpoint:
                - We can update the title, the body. This action can 
                    only be done by the assigner of this bug.
                - We can assign the bug to a user or update the assignee to 
                    another user. This action can only be done by the assigner
                    of this bug.
                - We can update the resolved status of this bug. This action
                    can be done by both the assigner and the assignee of this bug
                
        """,
        operation_summary="updates a bug",
        operation_id='bug_update', responses={200: serializers.BugDetailSerializer()})
    def partial_update(self, request, *args, **kwargs):
        user = self.request.user
        serializer = serializers.UpdateBugSerializer(instance=self.get_object(), data=request.data,
                                               partial=True, context={"user": user})
        serializer.is_valid(raise_exception=True)
        bug = serializer.save()
        return Response(data=serializers.BugDetailSerializer(bug).data, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_summary="deletes a bug",
        operation_description="This action can only be done by the assigner of this bug",
        operation_id='bug_delete', responses={204: None})
    def destroy(self, request, *args, **kwargs):
        if self.request.user != self.get_object().assigner:
            raise APIException(detail="you are not the creator of this bug", code=status.HTTP_401_UNAUTHORIZED)
        return super(BugAPI, self).destroy(request, *args, **kwargs)


class CommentAPI(ModelViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.CommentSerializer
    queryset = Comment.objects.all().order_by('-updated_at')
    http_method_names = ('post', 'delete')

    @swagger_auto_schema(
        request_body=serializers.CommentSerializer,
        operation_summary="adds a comment to a bug",
        operation_id='comment_create',
        responses={201: serializers.CommentSerializer()}
    )
    def create(self, request, *args, **kwargs):
        serializer = serializers.CommentSerializer(data=request.data, context={"user": request.user})
        serializer.is_valid(raise_exception=True)
        comment = serializer.save()
        return Response(data=serializers.CommentSerializer(comment).data, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        operation_summary="deletes a comment",
        operation_id='comment_delete', responses={204: None},
        operation_description="only the author of a comment can delete that comment")
    def destroy(self, request, *args, **kwargs):
        if self.request.user != self.get_object().user:
            raise APIException(detail="you are not the author of this comment", code=status.HTTP_401_UNAUTHORIZED)
        return super(CommentAPI, self).destroy(request, *args, **kwargs)


class SigninAPI(APIView):
    permission_classes = (AllowAny,)
    http_method_names = ('post',)

    @swagger_auto_schema(
        request_body=serializers.SigninSerializer,
        operation_summary="signs a user in",
        tags=['authentication'],
        operation_id='signin')
    def post(self, request, *args, **kwargs):
        serializer = serializers.SigninSerializer(data=request.data, context=dict(request=request))
        serializer.is_valid(raise_exception=True)
        data = serializer.save()
        return Response(data=dict(message="Login is successful", data=data), status=status.HTTP_200_OK)


class SignupAPI(APIView):
    permission_classes = (AllowAny,)
    http_method_names = ('post',)

    @swagger_auto_schema(
        request_body=serializers.SignupSerializer,
        operation_summary="creates new user account",
        tags=['authentication'],
        operation_id='signup',
        responses={201: serializers.UserSerializer()})
    def post(self, request, *args, **kwargs):
        serializer = serializers.SignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.save()
        return Response(data=dict(message="account has been created successfully", data=data),
                        status=status.HTTP_201_CREATED)


class SignoutAPI(APIView):
    permission_classes = (IsAuthenticated,)
    http_method_names = ('post',)

    @swagger_auto_schema(
        operation_summary="signs a user out",
        tags=['authentication'],
        operation_id='signout')
    def post(self, request, *args, **kwargs):
        serializer = serializers.SignOutSerializer(data=request.data, context=dict(request=request))
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(data=dict(message="you have been logged out successfully"),
                        status=status.HTTP_200_OK)
