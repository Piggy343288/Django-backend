import random
import requests
from piggySQL import models

from django.urls import path
from django.conf import settings
from django.shortcuts import render
from django.http import Http404, JsonResponse
from django.core.paginator import InvalidPage, Paginator

from haystack.query import EmptySearchQuerySet
from haystack.forms import FacetedSearchForm, ModelSearchForm

from .QuickDjango import b64encode, get_user, wx_url, token
from .QuickDjango import qrender, render, use, QJR, b64decode, logger


@logger.catch
def index(request):
    return qrender(request, "index.html", False)


@logger.catch
def msg_sec_check(query: str, user: models.User) -> dict:
    params = {
        "openid": b64decode(user.isWX),
        "scene": 1,
        "version": 2,
        "content": query
    }
    resp = requests.post(
        f"{wx_url}/wxa/msg_sec_check?access_token={token.access_token}", json=params)
    return resp.json()
