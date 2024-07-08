from django.urls import path, include
from rest_framework.routers import DefaultRouter
from authentication.views import UserViewSet

router = DefaultRouter()
router.register('users', UserViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
