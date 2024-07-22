from django.contrib import admin
from django.urls import path,include
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('account.urls')),
    path('token/refresh/',jwt_views.TokenRefreshView.as_view(), name ='token_refresh')

]
