from django.contrib.auth.models import User
from django.db import models
from django.utils.functional import cached_property


# Create your models here.


class Bug(models.Model):
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
    bug = models.ForeignKey(Bug, on_delete=models.CASCADE)
    title = models.CharField(max_length=100, default="")
    body = models.TextField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


