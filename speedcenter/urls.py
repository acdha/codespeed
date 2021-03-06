# -*- coding: utf-8 -*-

import os.path

from django.conf import settings
from django.conf.urls.defaults import url, patterns, include, handler404, handler500
from django.contrib import admin


admin.autodiscover()

urlpatterns = patterns('',
    (r'^admin/', include(admin.site.urls)),
)

if settings.DEBUG or settings.SERVE_STATIC:
    urlpatterns += patterns('',
        url(r'^media/(?:\d+/|)override/(?P<path>.*)$', 'django.views.static.serve',
            {'document_root': settings.OVERRIDE_MEDIA_ROOT}),
        url(r'^media/(?:\d+/|)(?P<path>.*)$', 'django.views.static.serve',
            {'document_root': settings.MEDIA_ROOT}),
        url(r'^admin_media/(?:[^/]+/|)(?P<path>.*)$', 'django.views.static.serve',
            {'document_root': os.path.join(os.path.dirname(admin.__file__),
                                                            'media')}))

urlpatterns += patterns('',
    (r'^', include('speedcenter.codespeed.urls')),
)
