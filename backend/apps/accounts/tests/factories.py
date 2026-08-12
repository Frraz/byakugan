"""Factories de usuários para testes."""

from __future__ import annotations

import factory
from django.contrib.auth import get_user_model

User = get_user_model()

DEFAULT_PASSWORD = "Byak-Str0ng-Pass!"


class UserFactory(factory.django.DjangoModelFactory):
    """Cria usuários usando o manager (hash de senha correto)."""

    class Meta:
        model = User
        skip_postgeneration_save = True

    email = factory.Sequence(lambda n: f"user{n}@byakugan.test")
    role = "viewer"

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        password = kwargs.pop("password", DEFAULT_PASSWORD)
        return model_class.objects.create_user(password=password, **kwargs)
