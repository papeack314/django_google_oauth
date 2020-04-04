import os
import urllib
import json
from django.http import HttpResponseRedirect
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.utils import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated


class HelloView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, response):
        content = {"message": "Hello, World!"}
        return Response(content)

class OauthCallback(APIView):
    """
    Google OAuthのコールバックview
    """
    def get(self, request):
        code = request.query_params.get("code", "")
        url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": os.environ["GOOGLE_OAUTH_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_OAUTH_CLIENT_SECRET"],
            "grant_type": "authorization_code",
            "redirect_uri": "http://localhost:8000/o/callback"
        }
        headers = {'Content-Type': 'application/json'}
        req = urllib.request.Request(url, json.dumps(data).encode(), headers)
        with urllib.request.urlopen(req) as res:
            body = res.read()
        body = json.loads(body.decode("utf-8"))
        access_token = body["access_token"]

        with urllib.request.urlopen("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + access_token) as response:
            data = json.loads(response.read().decode("utf-8"))
        
        if "error" in data:
            content = {
                "message": "wrong google token / this google token is already expired."
            }
            return Response(content, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=data["email"])
        except:
            user = User()
            user.username = data["email"]
            user.password = make_password(BaseUserManager().make_random_password())
            user.email = data["email"]
            user.save()
        
        token = RefreshToken.for_user(user)
        resp = HttpResponseRedirect(redirect_to='https://google.com')
        resp.set_cookie("user_name", user.username)
        resp.set_cookie("access_token", str(token.access_token))
        resp.set_cookie("refresh_token", str(token))
        resp.set_cookie("picture_url", data["picture"])
        return resp

