from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager


class MyAccountManager(BaseUserManager):
    def create_user(self, first_name, last_name, email, username, password=None):
        if not email:
            raise ValueError("Users must have an Email Address")

        if not username:
            raise ValueError("Users must have an Username")

        user = self.model(
            email = self.normalize_email(email),
            username = username,
            first_name = first_name,
            last_name = last_name,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password):
        user = self.create_user(
            email=self.normalize_email(email),
            username=username,
            password=password,
        )

        user.is_active = True
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class Account(AbstractBaseUser):
    first_name          = models.CharField(max_length=50)
    last_name           = models.CharField(max_length=50)
    username            = models.CharField(max_length=30, unique=True)
    email               = models.EmailField(verbose_name='Email Address', max_length=100, unique=True)
    date_joined         = models.DateTimeField(verbose_name='date joined', auto_now_add=True)
    last_login          = models.DateTimeField(verbose_name='last login', auto_now_add=True)
    is_admin            = models.BooleanField(default=False)
    is_active           = models.BooleanField(default=False)
    is_staff            = models.BooleanField(default=False)
    is_superuser        = models.BooleanField(default=False)
    # Must use above fields in custom user model

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username',]

    objects = MyAccountManager()

    def __str__(self):
        return self.email

    # required for custom user
    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True
