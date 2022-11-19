from django.urls import path
from rest_framework.routers import SimpleRouter
from Bugs import views

router = SimpleRouter()
router.register('bugs', viewset=views.BugAPI, basename="bugs")
router.register('comments', viewset=views.CommentAPI, basename="comments")


urlpatterns = [
    path('auth/signup/', views.SignupAPI.as_view(), name="signup"),
    path('auth/signin/', views.SigninAPI.as_view(), name="signin"),
    path('auth/signout/', views.SignoutAPI.as_view(), name="signout")
]


urlpatterns = urlpatterns + router.urls