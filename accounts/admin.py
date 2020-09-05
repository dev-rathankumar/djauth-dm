from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Account

# Register your models here.
class AccountAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'username', 'date_joined', 'last_login', 'is_active',)
    search_fields = ('email', 'first_name', 'last_name', 'username',)
    readonly_fields = ('date_joined', 'last_login',)
    list_display_links = ('email', 'first_name', 'last_name', 'username',)
    ordering = ('-date_joined',)

    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
admin.site.register(Account, AccountAdmin)
