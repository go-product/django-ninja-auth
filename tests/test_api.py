import json
import re
from datetime import datetime
from typing import Dict, Any, List

import pytest
from django.contrib.auth.models import User
from django.core import mail
from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse
from django.template import Template
from django.test.client import Client
from django.urls import ResolverMatch

pytestmark = [pytest.mark.django_db]


class TestClientResponse(JsonResponse):
    client: Client = ...
    request: Dict[str, Any] = ...
    templates: List[Template] = ...
    context: Dict[str, Any] = ...
    resolver_match: ResolverMatch

    def json(self) -> Dict[str, Any]:
        ...


def ecma_datetime_format(dt: datetime) -> str:
    return json.dumps(dt, cls=DjangoJSONEncoder)[1:-1]  # Surrounding quotes


def test_login_logout(admin_user: User, client: Client):
    response: TestClientResponse = client.post(
        "/api/auth/",
        data={"username": "admin", "password": "password"},
        content_type="application/json",
    )
    assert response.status_code == 200
    admin_user.refresh_from_db()
    assert response.json() == {
        "date_joined": ecma_datetime_format(admin_user.date_joined),
        "email": "admin@example.com",
        "first_name": "",
        "groups": [],
        "id": 1,
        "is_active": True,
        "is_staff": True,
        "is_superuser": True,
        "last_login": ecma_datetime_format(admin_user.last_login),
        "last_name": "",
        "user_permissions": [],
        "username": "admin",
    }
    response = client.delete("/api/auth/")
    assert response.status_code == 204


def test_me(admin_user: User, client: Client):
    client.force_login(admin_user)
    admin_user.refresh_from_db()
    response: TestClientResponse = client.get("/api/auth/me")
    assert response.json() == {
        "date_joined": ecma_datetime_format(admin_user.date_joined),
        "email": "admin@example.com",
        "first_name": "",
        "groups": [],
        "id": 1,
        "is_active": True,
        "is_staff": True,
        "is_superuser": True,
        "last_login": ecma_datetime_format(admin_user.last_login),
        "last_name": "",
        "user_permissions": [],
        "username": "admin",
    }


def test_request_password_reset(admin_user: User, client: Client):
    response: TestClientResponse = client.post(
        "/api/auth/request_password_reset",
        data={"email": admin_user.email},
        content_type="application/json",
    )
    assert response.status_code == 204
    assert len(mail.outbox) == 1
    message = mail.outbox[0]
    assert re.match(
        r"http://testserver/frontend/reset-password\?token=[\w-]+", message.body
    )


def test_reset_password(admin_user: User, client: Client):
    response: TestClientResponse = client.post(
        "/api/auth/request_password_reset",
        data={"email": admin_user.email},
        content_type="application/json",
    )
    message = mail.outbox[0]
    token = re.sub(
        r"http://testserver/frontend/reset-password\?token=([\w-]+)",
        r"\1",
        message.body,
    )
    response = client.post(
        "/api/auth/reset_password",
        data={
            "username": admin_user.get_username(),
            "new_password1": "more-secure-password",
            "new_password2": "more-secure-password",
            "token": token,
        },
        content_type="application/json",
    )
    admin_user.refresh_from_db()
    assert response.status_code == 200
    assert response.json() == {
        "date_joined": ecma_datetime_format(admin_user.date_joined),
        "email": "admin@example.com",
        "first_name": "",
        "groups": [],
        "id": 1,
        "is_active": True,
        "is_staff": True,
        "is_superuser": True,
        "last_login": ecma_datetime_format(admin_user.last_login),
        "last_name": "",
        "user_permissions": [],
        "username": "admin",
    }


def test_change_password(admin_user: User, client: Client):
    client.force_login(admin_user)
    response: TestClientResponse = client.post(
        "/api/auth/change_password",
        data={
            "old_password": "password",
            "new_password1": "more-secure-password",
            "new_password2": "more-secure-password",
        },
        content_type='application/json'
    )
    assert response.status_code == 200

def test_change_password_not_logged_in(admin_user: User, client: Client):
    response: TestClientResponse = client.post(
        "/api/auth/change_password",
        data={
            "old_password": "password",
            "new_password1": "more-secure-password",
            "new_password2": "more-secure-password",
        },
        content_type='application/jason'
    )
    assert response.status_code == 401

def test_change_password_wrong_password(admin_user: User, client: Client):
    client.force_login(admin_user)
    response: TestClientResponse = client.post(
        "/api/auth/change_password",
        data={
            "old_password": "wrong-password",
            "new_password1": "more-secure-password",
            "new_password2": "more-secure-password",
        },
        content_type='application/json'
    )

    assert response.status_code == 403
    assert response.json() == {'errors': {'old_password': []}}
