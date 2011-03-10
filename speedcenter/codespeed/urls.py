# -*- coding: utf-8 -*-
from django.conf.urls.defaults import *
from django.views.generic.simple import direct_to_template

from speedcenter.codespeed.feeds import LatestEntries
from speedcenter.codespeed.models import Project

feeds = { 'latest': LatestEntries }


urlpatterns = patterns('',
    url(r'^$', 'django.views.generic.list_detail.object_list', {"queryset": Project.objects.all()}),
    (r'^about/$', direct_to_template, {'template': 'about.html'}),
    # RSS for reports
    url(r'^feeds/(?P<url>.*)/$', 'django.contrib.syndication.views.feed',
        {'feed_dict': feeds},
        name="feeds"),
)

urlpatterns += patterns('speedcenter.codespeed.views',
    url(r'^(?P<project>[^/]+)/$',                 'home', name="project-detail"),
    url(r'^(?P<project>[^/]+)/reports/$',         'reports', name="reports"),
    # TODO: Unify changes/revision terminology
    url(r'^(?P<project>[^/]+)/changes/$',         'changes', name="changes-list"),
    url(r'^(?P<project>[^/]+)/changes/table/$',   'getchangestable', name='changes-table'),
    url(r'^(?P<project>[^/]+)/revision/$', 'revision_list', name='revision-list'),
    url(r'^(?P<project>[^/]+)/revision/(?P<revision>[^/]+)/$', 'revision_detail', name='revision-detail'),
    url(r'^(?P<project>[^/]+)/timeline/$',        'timeline', name="timeline"),
    url(r'^(?P<project>[^/]+)/timeline/json/$',   'gettimelinedata'),
    url(r'^(?P<project>[^/]+)/comparison/$',      'comparison', name="comparison"),
    url(r'^(?P<project>[^/]+)/comparison/json/$', 'getcomparisondata'),
    url(r'^(?P<project>[^/]+)/result/add/json/$', 'add_json_results'),
    url(r'^(?P<project>[^/]+)/result/add/$',      'add_result'),
)
