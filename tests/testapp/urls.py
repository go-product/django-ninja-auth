from django.urls import path
from ninja import NinjaAPI
from ninja.security import django_auth
from ninja_auth.api import router as auth_router


api = NinjaAPI(csrf=True, auth=django_auth)
api.add_router("/auth/", auth_router, auth=None)

urlpatterns = [
    path("api/", api.urls),
]
