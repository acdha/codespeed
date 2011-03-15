# -*- coding: utf-8 -*-
from django.conf.urls.defaults import *
from django.views.generic.simple import direct_to_template

from speedcenter.codespeed.feeds import LatestEntries
from speedcenter.codespeed.models import Project

feeds = { 'latest': LatestEntries }

urlpatterns = patterns('',
                       url(r'^$', 'django.views.generic.list_detail.object_list', {"queryset": Project.objects.all()}),
                       url(r'^about/$', direct_to_template, {'template': 'about.html'}, name="about-site"),
                       # RSS for reports
                       url(r'^feeds/(?P<url>.*)/$', 'django.contrib.syndication.views.feed',
                           {'feed_dict': feeds}, name="feeds"),
                       )

urlpatterns += patterns('speedcenter.codespeed.views',
    url(r'^(?P<project_slug>[^/]+)/$',                 'home', name="project-detail"),
    url(r'^(?P<project_slug>[^/]+)/reports/$',         'reports', name="reports"),
    # TODO: Unify changes/revision terminology
    url(r'^(?P<project_slug>[^/]+)/changes/$',         'changes', name="changes-list"),
    url(r'^(?P<project_slug>[^/]+)/changes/table/$',   'getchangestable', name='changes-table'),
    url(r'^(?P<project_slug>[^/]+)/revision/$', 'revision_list', name='revision-list'),
    url(r'^(?P<project_slug>[^/]+)/revision/(?P<revision>[^/]+)/$', 'revision_detail', name='revision-detail'),
    url(r'^(?P<project_slug>[^/]+)/timeline/$',        'timeline', name="timeline"),
    url(r'^(?P<project_slug>[^/]+)/timeline/json/$',   'gettimelinedata'),
    url(r'^(?P<project_slug>[^/]+)/comparison/$',      'comparison', name="comparison"),
    url(r'^(?P<project_slug>[^/]+)/comparison/json/$', 'getcomparisondata'),

    # TODO: Decide whether to stay backwards compatible with clients or move the add URLs under a project
    url(r'^result/add/json/$', 'add_json_results'),
    url(r'^result/add/$',      'add_result'),
)
