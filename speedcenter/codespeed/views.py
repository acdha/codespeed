# -*- coding: utf-8 -*-
from datetime import datetime
from itertools import islice
import json
import logging

from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse, Http404, HttpResponseNotAllowed, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render_to_response
from django.template import RequestContext
from django.views.generic.list_detail import object_detail, object_list

from speedcenter.codespeed import settings
from speedcenter.codespeed.models import Environment, Report
from speedcenter.codespeed.models import Project, Revision, Result, Executable, Benchmark


def home(request, project_slug=None, *args, **kwargs):
    project = get_object_or_404(Project, slug=project_slug)
    ec = {"project": project}
    return object_detail(request, queryset=Project.objects.all(),
                            slug=project.slug, extra_context=ec,
                            *args, **kwargs)

def no_environment_error():
    return render_to_response('codespeed/nodata.html', {
        'message': 'You need to configure at least one Environment. Please go to the <a href="../admin/codespeed/environment/">admin interface</a>'
    })

def no_default_project_error():
    return render_to_response('codespeed/nodata.html', {
        'message': 'You need to configure at least one one Project as default (checked "Track changes" field).<br />Please go to the <a href="../admin/codespeed/project/">admin interface</a>'
    })

def no_executables_error():
    return render_to_response('codespeed/nodata.html', {
        'message': 'There needs to be at least one executable'
    })

def no_data_found():
    return render_to_response('codespeed/nodata.html', {
        'message': 'No data found'
    })

def getbaselineexecutables(project):
    baseline = [{'key': "none", 'name': "None", 'executable': "none", 'revision': "none"}]

    for tagged_revision in project.revisions.exclude(tag=""):
        exe_pks = Result.objects.filter(revision=tagged_revision).values_list("executable", flat=True).order_by("executable").distinct()

        for exe in Executable.objects.filter(pk__in=exe_pks):
            exestring = str(exe)
            # BUG: This string formatting should be a templating behaviour
            if len(exestring) > 19:
                exestring = "%s..." % exestring[0:22]

            name = "%s %s" % (exestring, tagged_revision.tag)
            key = "%s+%s" % (exe.pk, tagged_revision.pk)

            baseline.append({
                'key': key,
                'executable': exe,
                'revision': tagged_revision,
                'name': name,
            })

    # move default to first place
    # BUG: def_baseline should be a property of the project
    if hasattr(settings, 'def_baseline') and settings.def_baseline is not None:
        try:
            for base in baseline:
                if base['key'] == "none":
                    continue
                exename = settings.def_baseline['executable']
                commitid = settings.def_baseline['revision']
                if base['executable'].name == exename and base['revision'].commitid == commitid:
                    baseline.remove(base)
                    baseline.insert(1, base)
                    break
        except KeyError:
            # TODO: write to server logs
            #error in settings.def_baseline
            pass

    return baseline

def getdefaultenvironment(project):
    default = project.environments.all()
    if not len(default):
        return 0
    default = default[0]
    if hasattr(settings, 'def_environment'):
        try:
            default = Environment.objects.get(name=settings.def_environment)
        except Environment.DoesNotExist:
            pass
    return default

def getdefaultexecutable(project):
    default = None
    if hasattr(settings, 'def_executable') and settings.def_executable is not None:
        try:
            default = Executable.objects.get(name=settings.def_executable)
        except Executable.DoesNotExist:
            pass
    if default is None:
        execquery = Executable.objects.filter(project=project)
        if len(execquery):
            default = execquery[0]

    return default

def get_tagged_executables(project):
    """
    Return a list of executables for the latest commit and every tagged release
    """

    executables = list(project.executables.all())

    latest_revision = project.revisions.order_by("-date")[0]

    for executable in executables:
        yield ("%s@%s" % (executable.pk, latest_revision.pk),
               "%s Latest" % executable.name,
               latest_revision,
               executable)

    for revision in project.revisions.exclude(pk=latest_revision.pk).exclude(tag="").order_by("-date"):
        for executable in executables:
            yield ("%s@%s" % (executable.pk, revision.pk),
                   "%s %s" % (executable.name, revision.tag),
                   revision,
                   executable)


def getcomparisondata(request, project_slug=None):
    if request.method != 'GET':
        return HttpResponseNotAllowed('GET')

    project = get_object_or_404(Project, slug=project_slug)

    compdata = {}

    for key, label, revision, exe in get_tagged_executables(project):
        compdata[key] = {}

        for env in project.environments.all():
            compdata[key][env.id] = {}

            for bench in project.benchmarks.order_by('name'):
                try:
                    # BUG: This will produce far too many queries - we should refactor it:
                    value = Result.objects.get(
                        environment=env,
                        executable=exe,
                        revision=revision,
                        benchmark=bench
                    ).value
                except Result.DoesNotExist:
                    value = None
                compdata[key][env.id][bench.id] = value

    return HttpResponse(json.dumps(compdata))


def comparison(request, project_slug=None):
    if request.method != 'GET':
        return HttpResponseNotAllowed('GET')

    project = get_object_or_404(Project, slug=project_slug)

    try:
        selected_bench_pks = [int(i) for i in request.GET.get("ben", "").split(",") if i]

        if 'exe' in request.GET:
            # This should be a list of "<Executable pk>@<Revision pk>" strings:
            selected_exe_keys = [i for i in request.GET.get("exe", "").split(",") if i]
        else:
            selected_exe_keys = None

        selected_env_pks = [int(i) for i in request.GET.get("env", "").split(",") if i]
        selected_chart = request.GET.get("chart", "normal bars")
        selected_baseline = request.GET.get("baseline", None)
        direction = request.GET.get("direction", None)
        if direction not in ('horizontal', 'vertical'):
            direction = getattr(settings, 'chart_orientation', 'vertical')
    except (TypeError, ValueError), e:
        return HttpResponseBadRequest(e)

    if not project.environments.exists():
        return no_environment_error()

    if not project.executables.exists():
        return no_executables_error()

    tagged_executables = get_tagged_executables(project)

    units_titles = project.benchmarks.values_list('units_title', flat=True).distinct()
    benchmarks = {}
    bench_units = {}
    for unit in units_titles:
        benchmarks[unit] = project.benchmarks.filter(units_title=unit)
        units = benchmarks[unit][0].units
        lessisbetter = benchmarks[unit][0].lessisbetter and ' (less is better)' or ' (more is better)'
        bench_units[unit] = [[b.id for b in benchmarks[unit]], lessisbetter, units]

    if not selected_bench_pks:
        selected_bench_pks = project.benchmarks.values_list("pk", flat=True).distinct()

    if not selected_env_pks:
        selected_env_pks = project.environments.values_list("pk", flat=True)

    charts = ['normal bars', 'stacked bars', 'relative bars']
    # Don't show relative charts as an option if there is only one executable
    # Relative charts need normalization
    if project.executables.count() == 1:
        charts.remove('relative bars')

    if selected_chart not in charts and getattr(settings, 'chart_type', None) in charts:
        selected_chart = settings.chart_type

    return render_to_response('codespeed/comparison.html', {
        'project': project,
        'selected_exe_keys': selected_exe_keys,
        'tagged_executables': [(i, j) for i,j,k,l in islice(tagged_executables, 20)],
        'selected_bench_pks': selected_bench_pks,
        'selected_env_pks': selected_env_pks,
        'default_environment': project.default_environment or project.environments[0],
        'executables': project.executables.all(),
        'benchmarks': benchmarks,
        'bench_units': json.dumps(bench_units),
        'charts': charts,
        'selected_baseline': selected_baseline,
        'selected_chart': selected_chart,
        'direction': direction
    }, context_instance=RequestContext(request))

def gettimelinedata(request, project_slug=None):
    if request.method != 'GET':
        return HttpResponseNotAllowed('GET')
    data = request.GET

    project = get_object_or_404(Project, slug=project_slug)

    timeline_list = {'error': 'None', 'timelines': []}

    executables = data.get('exe', "").split(",")
    if not filter(None, executables):
        timeline_list['error'] = "No executables selected"
        return HttpResponse(json.dumps( timeline_list ))

    environment = get_object_or_404(Environment, name=data.get('env'))

    benchmarks = []
    number_of_revs = data.get('revs', 10)

    if data['ben'] == 'grid':
        # TODO: This would be a lot easier if we added a foreign key or at
        #       least a manager method if we want to allow the same benchmark
        #       to be referenced by multiple projects
        project_benchmarks = Result.objects.filter(revision__project=project).values_list("benchmark", flat=True).distinct()
        benchmarks = Benchmark.objects.filter(pk__in=project_benchmarks).order_by("name")
        number_of_revs = 15
    else:
        benchmarks = [get_object_or_404(Benchmark, name=data['ben'])]

    baselinerev = None
    baselineexe = None
    if data.get('base') not in (None, 'none', 'undefined'):
        exeid, revid = data['base'].split("+")
        baselinerev = project.revisions.get(id=revid)
        baselineexe = project.executables.get(id=exeid)

    for bench in benchmarks:
        append = False
        lessisbetter = bench.lessisbetter and ' (less is better)' or ' (more is better)'
        timeline = {
            'benchmark':             bench.name,
            'benchmark_id':          bench.id,
            'benchmark_description': bench.description,
            'units':                 bench.units,
            'lessisbetter':          lessisbetter,
            'executables':           {},
            'baseline':              "None",
        }

        for executable in executables:
            resultquery = Result.objects.filter(
                    benchmark=bench,
                    revision__project=project
                ).filter(
                    environment=environment
                ).filter(
                    executable=executable
                ).select_related(
                    "revision"
                ).order_by('-revision__date')[:number_of_revs]
            if not len(resultquery):
                continue

            results = []
            for res in resultquery:
                std_dev = ""
                if res.std_dev is not None:
                    std_dev = res.std_dev
                results.append(
                    [str(res.revision.date), res.value, std_dev, res.revision.short_commit_id]
                )
            timeline['executables'][executable] = results
            append = True
        if baselinerev is not None and append:
            try:
                baselinevalue = Result.objects.get(revision__project=project,
                    executable=baselineexe,
                    benchmark=bench,
                    revision=baselinerev,
                    environment=environment
                ).value
            except Result.DoesNotExist:
                timeline['baseline'] = "None"
            else:
                # determine start and end revision (x axis) from longest data series
                results = []
                for exe in timeline['executables']:
                    if len(timeline['executables'][exe]) > len(results):
                        results = timeline['executables'][exe]
                end = results[0][0]
                start = results[len(results)-1][0]
                timeline['baseline'] = [
                    [str(start), baselinevalue],
                    [str(end), baselinevalue]
                ]
        if append:
            timeline_list['timelines'].append(timeline)

    if not len(timeline_list['timelines']):
        response = 'No data found for the selected options'
        timeline_list['error'] = response
    return HttpResponse(json.dumps( timeline_list ))


def timeline(request, project_slug=None):
    if request.method != 'GET':
        return HttpResponseNotAllowed('GET')

    project = get_object_or_404(Project, slug=project_slug)

    try:
        exe_pks = [int(i) for i in request.GET.get("exe", "").split(",") if i]

        defaultlast = int(request.GET.get("revs", 200))

        defaultbaseline = request.GET.get("base", None)

        default_benchmark_name = request.GET.get("ben", None)
    except (TypeError, ValueError), e:
        return HttpResponseBadRequest(e)

    lastrevisions = set((10, 50, 200, 1000))
    lastrevisions.add(defaultlast)

    checked_executables = Executable.objects.filter(project=project)
    if exe_pks:
        checked_executables = checked_executables.filter(pk__in=exe_pks)

    if not len(checked_executables):
        return no_executables_error()

    baseline = getbaselineexecutables(project)
    defaultbaseline = None
    if len(baseline) > 1:
        defaultbaseline = "%s+%s" % (baseline[1]['executable'].id, baseline[1]['revision'].id)

    benchmarks = project.benchmarks
    if not len(benchmarks):
        return no_data_found()

    if not default_benchmark_name:
        if len(benchmarks) == 1:
            default_benchmark_name = benchmarks[0].name
        else:
            default_benchmark_name = "grid"

    # Information for template
    executables = Executable.objects.filter(project=project)
    environments = project.environments.all()
    default_environment = project.default_environment
    if not default_environment and len(environments):
        default_environment = environments[0]

    return render_to_response('codespeed/timeline.html', {
        'checked_executables': checked_executables,
        'defaultbaseline': defaultbaseline,
        'baseline': baseline,
        'default_benchmark_name': default_benchmark_name,
        'default_environment': default_environment,
        'lastrevisions': sorted(lastrevisions),
        'defaultlast': defaultlast,
        'executables': executables,
        'benchmarks': benchmarks,
        'environments': environments
    }, context_instance=RequestContext(request))

def getchangestable(request, project_slug=None):
    try:
        project = Project.objects.get(slug=project_slug)
    except ObjectDoesNotExist:
        raise Http404()

    try:
        trendconfig = int(request.GET.get('tre', None))
        executable = project.executables.get(pk=int(request.GET['exe']))
        environment = Environment.objects.get(name=request.GET['env'])
        selectedrev = get_object_or_404(Revision, commitid=request.GET['rev'], project=project)
    except (KeyError, TypeError, ValueError, ObjectDoesNotExist):
        return HttpResponseBadRequest()

    report, created = Report.objects.get_or_create(executable=executable, environment=environment, revision=selectedrev)

    tablelist = report.get_changes_table(trendconfig)

    if not len(tablelist):
        return HttpResponse('<table id="results" class="tablesorter" style="height: 232px;"></table><p class="errormessage">No results for this parameters</p>')

    return render_to_response('codespeed/changes_table.html', {
        'tablelist': tablelist,
        'trendconfig': trendconfig,
        'rev': selectedrev,
        'exe': executable,
        'env': environment,
    }, context_instance=RequestContext(request))


def changes(request, project_slug=None):
    if request.method != 'GET':
        return HttpResponseNotAllowed('GET')

    project = get_object_or_404(Project, slug=project_slug)

    if not project.environments.exists():
        return no_environment_error()

    if not project.executables.exists():
        return no_executables_error()

    try:
        default_trend = request.GET.get("tre", None)
        default_environment = request.GET.get("env", None)
        default_executable = int(request.GET.get("exe", 0))
        selected_revision = request.GET.get("rev", None)
    except (ValueError, TypeError):
        return HttpResponseBadRequest()

    # Configuration of default parameters
    defaultchangethres = 3.0
    defaulttrendthres = 4.0
    if hasattr(settings, 'change_threshold') and settings.change_threshold is not None:
        defaultchangethres = settings.change_threshold
    if hasattr(settings, 'trend_threshold') and settings.trend_threshold is not None:
        defaulttrendthres = settings.trend_threshold

    trends = [5, 10, 20, 50, 100]

    if not default_environment:
        default_environment = project.default_environment or project.environments.all()[0]

    if not default_executable:
        default_executable = project.default_executable or project.executables.all()[0]

    recent_revisions = project.revisions.order_by('-date')
    if not recent_revisions:
        return no_data_found()

    return render_to_response('codespeed/changes.html', {
        "defaultchangethres": defaultchangethres,
        "default_environment": default_environment,
        "default_executable": default_executable,
        "defaulttrend": default_trend,
        "defaulttrendthres": defaulttrendthres,
        "project": project,
        "selected_revision": selected_revision,
        "recent_revisions": recent_revisions,
        "trends": trends,
    }, context_instance=RequestContext(request))

def revision_detail(request, project_slug=None, revision=None):
    """
    Simple accessor for Revision objects
    """
    qs = Revision.objects.filter(project__slug=project_slug)

    # TODO: Remove this outright when we can simply load JSON rather than HTML
    #       fragments
    if request.GET.get("format", False) == "table-fragment":
        template = "codespeed/changes_log.html"
    else:
        template = "codespeed/revision_detail.html"

    return object_detail(request, queryset=qs, slug=revision, slug_field="commitid", template_name=template)

def revision_list(request, project_slug=None):
    """
    Simple accessor for Revision objects
    """

    project = get_object_or_404(Project, slug=project_slug)

    ec = {
        "project": project,
    }

    return object_list(request, queryset=project.revisions.all(), paginate_by=20, extra_context=ec)


def reports(request, project_slug=None):
    if request.method != 'GET':
        return HttpResponseNotAllowed('GET')

    project = get_object_or_404(Project, slug=project_slug)

    return render_to_response('codespeed/reports.html', {
        'project': project,
        'reports': Report.objects.filter(revision__project=project).order_by('-revision__date')[:10],
    }, context_instance=RequestContext(request))


def getcommitlogs(rev, startrev, update=False):
    logs = []

    if rev.project.repo_type == 'S':
        from subversion import getlogs, updaterepo
    elif rev.project.repo_type == 'M':
        from mercurial import getlogs, updaterepo
    elif rev.project.repo_type == 'G':
        from git import getlogs, updaterepo
    elif rev.project.repo_type == 'H':
        from github import getlogs, updaterepo
    else:
        if rev.project.repo_type not in ("N", ""):
            logging.warning("Don't know how to retrieve logs from %s project",
                            rev.project.get_repo_type_display())
        return logs

    if update:
        updaterepo(rev.project)

    logs = getlogs(rev, startrev)

    # Remove last log because the startrev log shouldn't be shown
    if len(logs) > 1 and logs[-1].get('commitid') == startrev.commitid:
        logs.pop()

    return logs

def validate_result(item):
    '''
    Validates that a result dictionary has all needed parameters

    It returns a tuple
        Environment, False  when no errors where found
        Errormessage, True  when there is an error
    '''
    mandatory_data = [
        'commitid',
        'project',
        'executable',
        'benchmark',
        'environment',
        'result_value',
    ]

    response = {}
    error    = True

    for key in mandatory_data:
        if not key in item:
            return 'Key "' + key + '" missing from request', error
        elif key in item and item[key] == "":
            return 'Value for key "' + key + '" empty in request', error

    # Check that the Environment exists
    try:
        e = Environment.objects.get(name=item['environment'])
        error = False
        return e, error
    except Environment.DoesNotExist:
        return "Environment %(environment)s not found" % item, error

def create_report_if_enough_data(rev, exe, e):
    # Trigger Report creation when there are enough results
    last_revs = Revision.objects.filter(project=rev.project).order_by('-date')[:2]
    if len(last_revs) > 1:
        current_results = rev.results.filter(executable=exe, environment=e)
        last_results = last_revs[1].results.filter(executable=exe,environment=e)
        # If there is are at least as many results as in the last revision,
        # create new report
        if len(current_results) >= len(last_results):
            logging.debug("create_report_if_enough_data: About to create new report")
            report, created = Report.objects.get_or_create(
                executable=exe, environment=e, revision=rev
            )
            report.full_clean()
            report.save()
            logging.debug("create_report_if_enough_data: Created new report.")

def save_result(data):
    res, error = validate_result(data)
    if error:
        return res, True
    else:
        assert(isinstance(res, Environment))
        e = res

    p, created = Project.objects.get_or_create(slug=data["project"])
    b, created = Benchmark.objects.get_or_create(name=data["benchmark"])

    try:
        rev = p.revisions.get(commitid=data['commitid'])
    except Revision.DoesNotExist:
        rev = Revision(project=p, commitid=data['commitid'],
                        date=data.get("revision_date", datetime.now()))

        # Attempt to retrieve revision info from the back-end VCS, since we
        # want that to always take priority over what the client may have
        # passed in:
        try:
            logs = getcommitlogs(rev, rev, update=True)

            if logs:
                rev.author  = logs[0]['author']
                rev.date    = logs[0]['date']
                rev.message = logs[0]['message']
        except StandardError, e:
            logging.warning("unable to save revision %s info: %s", rev, e,
                            exc_info=True)

        rev.full_clean()
        rev.save()

    if 'revision_links' in data:
        for k, v in data['revision_links'].items():
            rev.links.get_or_create(title=k, url=v)

    exe, created = Executable.objects.get_or_create(
        name=data['executable'],
        project=p
    )

    try:
        r = Result.objects.get(revision=rev,executable=exe,benchmark=b,environment=e)
    except Result.DoesNotExist:
        r = Result(revision=rev,executable=exe,benchmark=b,environment=e)

    r.value = data["result_value"]
    if 'result_date' in data:
        r.date = data["result_date"]
    else:
        r.date = datetime.now()

    r.std_dev = data.get('std_dev')
    r.val_min = data.get('min')
    r.val_max = data.get('max')

    r.full_clean()
    r.save()

    return (rev, exe, e), False

def add_result(request):
    if request.method != 'POST':
        return HttpResponseNotAllowed('POST')
    data = request.POST

    response, error = save_result(data)
    if error:
        return HttpResponseBadRequest(response)
    else:
        create_report_if_enough_data(response[0], response[1], response[2])
        logging.debug("add_result: completed")
        return HttpResponse("Result data saved successfully", status=202)

def add_json_results(request):
    if request.method != 'POST':
        return HttpResponseNotAllowed('POST')
    data = json.loads(request.POST['json'])
    logging.info("add_json_results request with %d entries." % len(data))

    unique_reports = set()
    i = 0
    for result in data:
        i += 1
        logging.debug("add_json_results: save item %d." % i)
        response, error = save_result(result)
        if error:
            logging.debug(
                "add_json_results: could not save item %d because %s" % (
                i, response))
            return HttpResponseBadRequest(response)
        else:
            unique_reports.add(response)

    logging.debug("add_json_results: about to create reports")
    for rep in unique_reports:
        create_report_if_enough_data(rep[0], rep[1], rep[2])

    logging.debug("add_json_results: completed")

    return HttpResponse("All result data saved successfully", status=202)

