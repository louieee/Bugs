from django.contrib.auth.models import User
from django.db import models
from django.utils.functional import cached_property


# Create your models here.


class Bug(models.Model):
    """
        Assumptions:
            - when creating a bug, the resolved status is added to the
                payload because a bug should be unresolved on creation.
            - an assignee can ONLY resolve a bug and can do nothing else
            - an assigner can update/delete a bug
            - an assigner cannot assign a bug to himself
            - an assignee cannot delete a bug
            - when an assigner and an assignee are deleted, we should not delete the bug,
                because the bug should be kept for reference purpose.

    """
    title = models.CharField(max_length=100, default="", blank=True)
    body = models.TextField(blank=True)
    resolved = models.BooleanField(default=False)
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="assignee")
    assigner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="assigner")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @cached_property
    def comments(self):
        return Comment.objects.filter(bug=self).order_by('-updated_at')


class Comment(models.Model):
    """
        Assumptions:
            - when a bug is deleted, we need to delete all comments associated with the bug
                because it will be irrelevant to keep the comments of a bug that doesn't exist
            - when the author of a comment is deleted, we should not delete the comments made by
                that author because the comments are relevant to the bugs. They can be solutions
                to the bugs just as it is on stack overflow. So setting the user to null is a fallback
                for a deleted user.
    """
    bug = models.ForeignKey(Bug, on_delete=models.CASCADE)
    title = models.CharField(max_length=100, default="")
    body = models.TextField()
    author = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
