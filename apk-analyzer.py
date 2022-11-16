#!/usr/bin/python3

import argparse
import os
import subprocess
import sys
import re
import xml.etree.ElementTree as ET
import datetime
import glob
import cgi
from colored import attr, bg, fg


############################### FUNCTIONS ###############################
def loadTemplates():
    for tpl in t_templates:
        fp = open( tpl )
        t_templates_str[ os.path.basename(tpl) ] = fp.read()
        fp.close()

def renderTemplate( tpl, datas, escape=False ):
    tpl = '_' + tpl + '.html'
    if not tpl in t_templates_str:
        return False
    render = t_templates_str[tpl]
    for k,v in datas.items():
        if escape:
            v = cgi.escape( v )
        render = re.sub( '{{\s*'+k+'\s*}}', v, render )
    return render

def saveReport( report ):
    fp = open( output_directory+'/report.html', 'w' )
    fp.write( report )
    fp.close()

def format_bytes( size ):
    units = ['b', 'kb', 'mb', 'gb', 'tb']
    i = 0
    while size>=1024 and i<4:
        size = size / 1024
        i = i + 1
    return str(round(size,2)) + units[i]
############################### FUNCTIONS ###############################


############################### BASIC INFOS ###############################
def getBuild():
    if 'platformBuildVersionCode' in manifest.attrib:
        version = manifest.attrib['platformBuildVersionCode']
    elif 'compileSdkVersion' in manifest.attrib:
        version = manifest.attrib['compileSdkVersion']
    else:
        version = '?'

    return version
############################### BASIC INFOS ###############################


############################### PERMISSIONS ###############################
def listPermissionsCreated():
    output = ''
    t_all = manifest.findall('permission')

    for obj in t_all:
        if not 'protectionLevel' in obj.attrib:
            c = 'warning'
            infos = 'protectionLevel is not specified, other apps can use it'
        elif obj.attrib['protectionLevel'] != 'signature':
            c = 'warning'
            infos = 'protectionLevel is not "signature"", other apps can use it'
        else:
            c = ''
            infos = ''

        p = ET.tostring(obj, encoding='unicode', method='xml').strip()
        d = { 'class':c, 'perm':p, 'infos':infos }
        output = output + renderTemplate( 'permission_single', d, True )

    return output

def listPermissionsUsed():
    output = ''
    t_warning = {'android.permission.READ_EXTERNAL_STORAGE':'external storage permission','android.permission.WRITE_EXTERNAL_STORAGE':'external storage permission','android.permission.INTERNET':'webview permission'}
    t_all = manifest.findall('uses-permission')

    for obj in t_all:
        c = ''
        infos = ''
        for k,v in t_warning.items():
            if k == obj.attrib['name']:
                infos = v
                c = 'warning'

        p = ET.tostring(obj, encoding='unicode', method='xml').strip()
        d = { 'class':c, 'perm':p, 'infos':infos }
        output = output + renderTemplate( 'permission_single', d, True )

    return output

def listPermissionsRequired():
    output = ''
    t_all = manifest.findall('permission')
    t_perm = []
    t_term = []
    t_noterm = []
    for elem in manifest.iter():
        if 'permission' in elem.attrib:
            t_perm.append( elem )
            if grep_term in elem.attrib['permission']:
                t_term.append( elem )
                t_perm.append( elem )
            else:
                t_noterm.append( elem )

    t_unwarn = ['android.permission','com.google.android','com.google.firebase','com.amazon.']

    for obj in t_perm:
        c = 'warning'
        infos = 'permission used but not created'
        for perm in t_all:
            if obj.attrib['permission'] == perm.attrib['name']:
                c = ''
                infos = ''
            for w in t_unwarn:
                if w in obj.attrib['permission']:
                    c = ''
                    infos = ''

        p = ET.tostring(obj, encoding='unicode', method='xml').strip()
        d = { 'class':c, 'perm':p, 'infos':infos }
        output = output + renderTemplate( 'permission_single', d, True )

    return output

def listPermissions():
    return listPermissionsCreated(), listPermissionsUsed(), listPermissionsRequired()
############################### PERMISSIONS ###############################


############################### ACTIVITIES ###############################
def saveActivities():
    fp = open( output_directory+'/activities', 'w' )
    fp.write( '\n'.join(sorted(t_activities)) )
    fp.close()

def isActivityExported( obj ):
    if 'exported' in obj.attrib:
        # infos = 'exported param'
        is_exported = ( obj.attrib['exported'].lower() == "true" )
    elif obj.findall('intent-filter'):
        # extra = 'intent-filter'
        is_exported = True
    else:
        is_exported = False

    return is_exported

def isActivityEnabled( obj ):
    if 'enabled' in obj.attrib:
        is_enabled = ( obj.attrib['enabled'].lower() == "true" )
    else:
        is_enabled = True

    return is_enabled

def listActivitiesManifest():
    output = ''
    t_all = manifest.findall('application/activity') + manifest.findall('application/activity-alias')

    for obj in t_all:
        t_activities.append( obj.attrib['name'] )
        if isActivityExported(obj) and isActivityEnabled(obj):
            c = 'warning'
        else:
            c = ''

        p = ET.tostring(obj, encoding='unicode', method='xml').strip()
        d = { 'class':c, 'activity':p }
        output = output + renderTemplate( 'activity_single', d, True )

    return output

def listActivitiesSourceGrep():
    cmd = 'cd "' + t_datas['directory'] + '" ; egrep -Iroh "' + t_datas['package_name_short'] + '[a-zA-Z0-9_\.]*Activity" "'+t_datas['source_path']+'" | egrep -v "_Bind|databinding" | sort -fu 2>/dev/null'
    print(cmd)
    try:
        output = subprocess.check_output( cmd, shell=True ).decode('utf-8')
        # print(output)
    except Exception as e:
        # sys.stdout.write( "%s[-] error occurred: %s%s\n" % (fg('red'),e,attr(0)) )
        return ''

    t_new = []
    for obj in output.split("\n"):
        obj = obj.strip()
        if not len(obj):
            continue
        if not obj in t_activities:
            t_new.append( obj )
            t_activities.append( obj )

    return '<br/>'.join(t_new)
############################### ACTIVITIES ###############################


############################### SERVICES ###############################
def saveServices():
    fp = open( output_directory+'/services', 'w' )
    fp.write( '\n'.join(sorted(t_services)) )
    fp.close()

def isServiceExported( obj ):
    if 'exported' in obj.attrib:
        # infos = 'exported param'
        is_exported = ( obj.attrib['exported'].lower() == "true" )
    elif obj.findall('intent-filter'):
        # extra = 'intent-filter'
        is_exported = True
    else:
        is_exported = False

    return is_exported

def isServiceEnabled( obj ):
    if 'enabled' in obj.attrib:
        is_enabled = ( obj.attrib['enabled'].lower() == "true" )
    else:
        is_enabled = True

    return is_enabled

def listServicesManifest():
    output = ''
    t_all = manifest.findall('application/service')

    for obj in t_all:
        t_services.append( obj.attrib['name'] )
        if isServiceExported(obj) and isServiceEnabled(obj):
            c = 'warning'
        else:
            c = ''

        p = ET.tostring(obj, encoding='unicode', method='xml').strip()
        d = { 'class':c, 'service':p }
        output = output + renderTemplate( 'service_single', d, True )

    return output

def listServicesSourceGrep():
    cmd = 'cd "' + t_datas['directory'] + '" ; egrep -Iroh "' + t_datas['package_name_short'] + '[a-zA-Z0-9_\.]*Service" "'+t_datas['source_path']+'" | sort -fu 2>/dev/null'
    print(cmd)
    try:
        output = subprocess.check_output( cmd, shell=True ).decode('utf-8')
        # print(output)
    except Exception as e:
        # sys.stdout.write( "%s[-] error occurred: %s%s\n" % (fg('red'),e,attr(0)) )
        return ''

    t_new = []
    for obj in output.split("\n"):
        obj = obj.strip()
        if not len(obj):
            continue
        if not obj in t_services:
            t_new.append( obj )
            t_services.append( obj )

    return '<br/>'.join(t_new)
############################### SERVICES ###############################


############################### RECEIVERS ###############################
def saveReceivers():
    fp = open( output_directory+'/receivers', 'w' )
    fp.write( '\n'.join(sorted(t_receivers)) )
    fp.close()

def isReceiverExported( obj ):
    if 'exported' in obj.attrib:
        # infos = 'exported param'
        is_exported = ( obj.attrib['exported'].lower() == "true" )
    elif obj.findall('intent-filter'):
        # extra = 'intent-filter'
        is_exported = True
    else:
        is_exported = False

    return is_exported

def isReceiverEnabled( obj ):
    if 'enabled' in obj.attrib:
        is_enabled = ( obj.attrib['enabled'].lower() == "true" )
    else:
        is_enabled = True

    return is_enabled

def listReceiversManifest():
    output = ''
    t_all = manifest.findall('application/receiver')

    for obj in t_all:
        t_receivers.append( obj.attrib['name'] )
        if isReceiverExported(obj) and isReceiverEnabled(obj):
            c = 'warning'
        else:
            c = ''

        p = ET.tostring(obj, encoding='unicode', method='xml').strip()
        d = { 'class':c, 'receiver':p }
        output = output + renderTemplate( 'receiver_single', d, True )

    return output

def listReceiversSourceGrep():
    cmd = 'cd "' + t_datas['directory'] + '" ; egrep -Iroh "' + t_datas['package_name_short'] + '[a-zA-Z0-9_\.]*Receiver" "'+t_datas['source_path']+'" | sort -fu 2>/dev/null'
    print(cmd)
    try:
        output = subprocess.check_output( cmd, shell=True ).decode('utf-8')
        # print(output)
    except Exception as e:
        # sys.stdout.write( "%s[-] error occurred: %s%s\n" % (fg('red'),e,attr(0)) )
        return ''

    t_new = []
    for obj in output.split("\n"):
        obj = obj.strip()
        if not len(obj):
            continue
        if not obj in t_receivers:
            t_new.append( obj )
            t_receivers.append( obj )

    return '<br/>'.join(t_new)
############################### RECEIVERS ###############################


############################### PROVIDERS ###############################
def saveProviders():
    fp = open( output_directory+'/providers', 'w' )
    fp.write( '\n'.join(sorted(t_providers)) )
    fp.close()

def isProviderExported( obj ):
    if 'exported' in obj.attrib:
        # infos = 'exported param'
        is_exported = ( obj.attrib['exported'].lower() == "true" )
    elif obj.findall('intent-filter'):
        # extra = 'intent-filter'
        is_exported = True
    else:
        is_exported = False

    return is_exported

def isProviderEnabled( obj ):
    if 'enabled' in obj.attrib:
        is_enabled = ( obj.attrib['enabled'].lower() == "true" )
    else:
        is_enabled = True

    return is_enabled

def listProvidersManifest():
    output = ''
    t_all = manifest.findall('application/provider')

    for obj in t_all:
        t_providers.append( obj.attrib['authorities'] )
        if isProviderExported(obj) and isProviderEnabled(obj):
            c = 'warning'
        else:
            c = ''

        p = ET.tostring(obj, encoding='unicode', method='xml').strip()
        d = { 'class':c, 'provider':p }
        output = output + renderTemplate( 'provider_single', d, True )

    return output

def listProvidersSourceGrep():
    cmd = 'cd "' + t_datas['directory'] + '" ; egrep -Iroh "' + t_datas['package_name_short'] + '[a-zA-Z0-9_\.]*Provider" "'+t_datas['source_path']+'" | sort -fu 2>/dev/null'
    print(cmd)
    try:
        output = subprocess.check_output( cmd, shell=True ).decode('utf-8')
        # print(output)
    except Exception as e:
        # sys.stdout.write( "%s[-] error occurred: %s%s\n" % (fg('red'),e,attr(0)) )
        return ''

    t_new = []
    for obj in output.split("\n"):
        obj = obj.strip()
        if not len(obj):
            continue
        if not obj in t_providers:
            t_new.append( obj )
            t_providers.append( obj )

    return '<br/>'.join(t_new)

def getProvidersURIs():
    t_uri = []

    cmd = 'cd "' + t_datas['directory'] + '" ; egrep -Ihro "content://[a-zA-Z0-9_\-\/\.]+" "'+t_datas['source_path']+'" 2>/dev/null'
    print(cmd)

    try:
        output = subprocess.check_output( cmd, shell=True ).decode('utf-8')
        # print(output)
    except Exception as e:
        # sys.stdout.write( "%s[-] error occurred: %s%s\n" % (fg('red'),e,attr(0)) )
        return '<br/>'.join(t_uri)

    for l in output.split("\n"):
        if not len(l):
            continue
        tiktok = ''
        l = l.strip().strip('/').replace( 'content://','' )
        t_split = l.split('/')
        for token in t_split:
            tiktok = tiktok + '/' + token
            tiktok = tiktok.strip('/')
            uri1 = 'content://' + tiktok
            if not uri1 in t_uri:
                t_uri.append( uri1 )
            # uri2 = 'content://' + tiktok + '/'
            # if not uri2 in t_uri:
            #     t_uri.append( uri2 )

    return '<br/>'.join(t_uri)
############################### PROVIDERS ###############################


############################### INTERESTING FILES ###############################
t_files_warning = ['conf','secret','pass','key','auth','.cer','.crt','.pem','prod','debug']
t_files_ignore = ['.edges','.ktx','.scw','.vsh','.fsh','.shader','.dict','abp.txt','crashlytics-build.properties','tzdb.dat','.snsr','.alyp','.alyg','.frag','.vert','.gmt','.kml','.traineddata','.glsl','.glb','.css','.otf','.aac','.mid','.ogg','.m4a','.m4v','.ico','.gif','.jpg','.jpeg','.png','.bmp','.svg','.avi','.mpg','.mpeg','.mp3','.woff','.woff2','.ttf','.eot','.mp3','.mp4','.wav','.mpg','.mpeg','.avi','.mov','.wmv' ]

def _listFiles( dir ):
    t_all = []
    t_files = []

    # r=root, d=directories, f=files
    for r, d, f in os.walk( dir ):
        for file in f:
            filepath = os.path.join(r,file)
            filename = filepath.replace(args.directory+'/','')
            # filename = filepath.replace(' ','\ ')
            filesstats = os.stat( filepath )
            filesize = format_bytes( filesstats.st_size )
            t_all.append( {'filename':filename,'filesize':filesize} )
            if not filesstats.st_size:
                ignore = True
            else:
                ignore = False
                for i in t_files_ignore:
                    if i in filename.lower():
                        ignore = True
            if not ignore:
                t_files.append( {'filename':filename,'filesize':filesize} )

    return t_all,t_files

def getFileList( path ):
    output = ''
    t_all,t_files = listDirectory( path )

    for file in t_files:
        file['class'] = ''
        for w in t_files_warning:
            if w in file['filename'].lower():
                file['class'] = 'warning'

        render = renderTemplate( 'file_single', file, True )
        output = output + render

    return output

def listFiles( t_path ):
    output = ''

    for path in t_path:
        filelist = ''
        t_all,t_files = _listFiles( args.directory+path )

        for file in t_files:
            file['class'] = ''
            for w in t_files_warning:
                if w in file['filename'].lower():
                    file['class'] = 'warning'

            render = renderTemplate( 'file_single', file, True )
            filelist = filelist + render

        output = output + renderTemplate( 'files', {'path':path,'file_list':filelist,'n_display':str(len(t_files)),'n_total':str(len(t_all))} )

    return output
############################### INTERESTING FILES ###############################


############################### GREP ###############################
t_regexp = {
    'external_call': [
        '([^a-zA-Z0-9](OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|ARBITRARY)[^a-zA-Z0-9])',
        '(@(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|ARBITRARY)\()',
    ],
    'intent': ['(new Intent|new android\.content\.Intent|PendingIntent|sendBroadcast|sendOrderedBroadcast|startActivity|resolveActivity|createChooser|startService|bindService|registerReceiver)'],
    'webview': ['(setAllowContent|setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLS|setJavascriptEnabled|setPluginState|setSavePassword|JavascriptInterface|loadUrl|setPluginsEnabled|setPluginState|shouldOverrideUrlLoading)'],
    'internal_storage': ['(MODE_|getPreferences|getDefaultSharedPreferences|createTempFile|SQLiteDatabase|openOrCreateDatabase|execSQL|rawQuery)'],
    'external_storage': ['(EXTERNAL_STORAGE|EXTERNAL_CONTENT|getExternal)'],
    'log': ['(Log\.)'],
    'slog': ['(Slog\.)'],
    'event_log': ['(EventLog\.)'],
    'timber': ['(Timber\.)'],
    'certificate': ['(CertificatePinner|HostnameVerifier|X509Certificate|CertificatePinner|networkSecurityConfig|network-security-config|onReceivedSslError)'],
    # 'crypto': [''],
    'package': ['(vnd\.android\.package-archive)'],
    'takeovers': ['(amazonaws|azurewebsites|cloudapp|trafficmanager|herokuapp|cloudfront|digitaloceanspace|storage\.(cloud|google)|firebaseio\.com)'],
    'keys': [
        "([a-zA-Z0-9._-]*s3[a-z0-9.-]*\.amazonaws\.com[\\]?/?[a-zA-Z0-9._-]+?)",
        "(xox[pboa]-[0-9]{10,12}-[0-9]{10,12}(-[0-9]{10,12})?-[a-zA-Z0-9]{24,32})",
        "(T[a-zA-Z0-9_]{8}[\\]?/B[a-zA-Z0-9_]{8}[\\]?/[a-zA-Z0-9_]{24})",
        "((AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,})",
        "([psr]k_live_[0-9a-zA-Z]{24,34})",
        "((AC|SK)[0-9a-f]{32})",
        "(AIza[0-9A-Za-z_-]{35})",
        "([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)",
        "(([gG][oO][oO][gG][lL][eE]).{0,20}[ '\\\"=:\(\[{]+.{0,5}[0-9a-zA-Z_-]{24})",
        "(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})",
        "([0-9a-f]{32}-us[0-9]{1,2})",
        "(key-[0-9a-zA-Z]{32})",
        "(sq0(atp|csp)-[0-9A-Za-z_-]{22,43})",
        "(EAAA[0-9a-zA-Z_-]{60})",
        "(access_token\$(live|production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32})",
        "([^0-9a-zA-Z_-][AE][0-9a-zA-Z_-]{79})",
        "(A21AA[0-9a-zA-Z_-]{92})",
        "(([fF][aA][cC][eE][bB][oO][oO][kK]).{0,20}[ '\\\"=:(\[{]+.{0,5}[0-9a-f]{32})",
        "(EAACEdEose0cBA[0-9A-Za-z]+)",
        "([0-9]{10,20}\|[a-zA-Z0-9-]{20,30})",
        "(([tT][wW][iI][tT][tT][eE][rR]).{0,20}[ '\\\"=:(\[{]+.{0,5}[0-9a-zA-Z]{35,44})",
        "(([tT][wW][iI][tT][tT][eE][rR]).{0,20}[ '\\\"=:(\[{]+.{0,5}[1-9][0-9]+-[0-9a-zA-Z]{24,40})",
        "(AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%=\+]+)",
        "(([gG][iI][tT][hH][uU][bB]).{0,20}[ '\\\"=:(\[{]+.{0,5}[0-9a-zA-Z]{35,40})",
        "(([hH][eE][rR][oO][kK][uU]).{0,20}[ '\\\"=:(\[{]+.{0,5}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
        "([a-z\+]{3,}:[/]{1,3}[^:'\" ]{2,}:[^@'\\\" ]{3,}@[^'\" ]+)",
        "(ya29\.[0-9A-Za-z_-]+)",
        "(sk_live_[0-9a-z]{32})",
        "(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        "([a-zA-Z0-9_-]+\.(firebaseio|azurewebsites|cloudapp|trafficmanager|herokuapp|cloudfront)\.(com|net))",
        "(\-\-\-\-\-BEGIN[ ]+[A-Z]*[ ]*PRIVATE[ ]+KEY)",
        "([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        "(ey[A-Za-z0-9_=-]+\.ey[A-Za-z0-9_=-]+\.?[A-Za-z0-9_.+/=-]*)"
    ],
    # 'urls': [''],
    'ips': ['([0-9]{1,3}\s*,\s*){3,})'],
    'strings': ["(['\\\"][^'\\\"]+%[\.0-9]*[scfdlux][^'\\\"]+)"],
    'parameters': ['(putExtra|getBundleExtra|getBooleanExtra|getDoubleExtra|getIntExtra|getShortExtra|getStringExtra|getLongExtra|getFloatExtra|getCharExtra|getByteExtra|removeExtra|getCharSequenceExtra|getParcelableExtra|getBooleanArrayExtra|getCharArrayExtra|getByteArrayExtra|getCharSequenceArrayExtra|getCharSequenceArrayListExtra|getDoubleArrayExtra|getFloatArrayExtra|getIntArrayExtra|getIntegerArrayListExtra|getParcelableArrayListExtra|getParcelableArrayExtra|getSerializableExtra|getShortArrayExtra|getStringArrayExtra|getStringArrayListExtra|putIntegerArrayListExtra|putParcelableArrayListExtra|putStringArrayListExtra)'],
    'url_parameters': ['([&\?][a-zA-Z0-9_\-]+=)'],
    'file_manipulation': ['((get|set|open|add|new)[a-zA-Z0]*(File|URI|Stream|Image|Document|Dir|Content|Url)[a-zA-Z0]*)'],
}


def doGrep( wanted ):
    if not wanted in t_regexp:
        return ''

    output = ''

    for regexp in t_regexp[wanted]:
        cmd = 'cd "' + t_datas['directory'] + '" ; egrep -Irn "' + regexp + '" "'+t_datas['source_path']+'" 2>/dev/null'
        print(cmd)
        try:
            o = subprocess.check_output( cmd, shell=True ).decode('utf-8')
            # print(o)
        except Exception as e:
            # sys.stdout.write( "%s[-] error occurred: %s%s\n" % (fg('red'),e,attr(0)) )
            continue

        output = output + displayGrep( o.strip(), regexp )

    return output

def displayGrep( grep_result, regexp ):
    output = ''

    for grep in grep_result.split("\n"):
        tmp = grep.split(':')
        filepath = tmp[0]
        line = tmp[1]
        content = ':'.join(tmp[2:])

        content = re.sub( regexp, 'ABRACADABRA1\\1ABRACADABRA2', content )

        output = output + renderTemplate( 'grep_line2', {'filepath':filepath,'line':line,'content':content}, True )
        output = output.replace( 'ABRACADABRA1', '<span class="grep_keyword">' ).replace( 'ABRACADABRA2', '</span>' )

    return output
############################### GREP ###############################


############################### PARAMETERS ###############################
def saveParameters():
    fp = open( output_directory+'/parameters', 'w' )
    fp.write( '\n'.join(sorted(t_parameters)) )
    fp.close()

def getParameters():
    t_parameters = []
    t_command = [
        'cd "' + t_datas['directory'] + '" ; egrep -roIh "(putExtra|getBundleExtra|getBooleanExtra|getDoubleExtra|getIntExtra|getShortExtra|getStringExtra|getLongExtra|getFloatExtra|getCharExtra|getByteExtra|removeExtra|getCharSequenceExtra|getParcelableExtra|getBooleanArrayExtra|getCharArrayExtra|getByteArrayExtra|getCharSequenceArrayExtra|getCharSequenceArrayListExtra|getDoubleArrayExtra|getFloatArrayExtra|getIntArrayExtra|getIntegerArrayListExtra|getParcelableArrayListExtra|getParcelableArrayExtra|getSerializableExtra|getShortArrayExtra|getStringArrayExtra|getStringArrayListExtra|putIntegerArrayListExtra|putParcelableArrayListExtra|putStringArrayListExtra)\s*\(\s*[\'\\\"]{1}[a-zA-Z0-9_-]+[\'\\\"]" "'+t_datas['source_path']+'" | cut -d "(" -f 2 | tr -d "\'\\\""',
        'cd "' + t_datas['directory'] + '" ; egrep -roIh "([&\?][a-zA-Z0-9_\-]+=)" "'+t_datas['source_path']+'" | grep -v "u00" | tr -d \'?&=\' 2>/dev/null'
    ]

    for cmd in t_command:
        print(cmd)
        try:
            output = subprocess.check_output( cmd, shell=True ).decode('utf-8')
            # print(output)
        except Exception as e:
            # sys.stdout.write( "%s[-] error occurred: %s%s\n" % (fg('red'),e,attr(0)) )
            continue

        for p in output.split('\n'):
            p = p.strip()
            if len(p) and not p in t_parameters:
                t_parameters.append( p )

    return sorted(t_parameters)


############################### PARAMETERS ###############################


parser = argparse.ArgumentParser()
parser.add_argument( "-d","--directory",help="source directory" )
parser.add_argument( "-t","--term",help="term referencing the editor" )
parser.add_argument( "-c","--command",help="display commands to run", action="store_true" )
parser.add_argument( "-m","--mod",help="mod to run" )
parser.parse_args()
args = parser.parse_args()

if args.mod:
    mod = args.mod
else:
    mod = 'parosfw'

if args.command:
    display_commands = True
else:
    display_commands = False

if not args.directory:
    parser.error( 'source directory is missing' )

args.directory = args.directory.rstrip('/')
output_directory = args.directory
script_dir = os.path.dirname(os.path.abspath(__file__))

src_manifest = args.directory + '/' + 'AndroidManifest.xml'
if not os.path.isfile(src_manifest):
    parser.error( 'Manifest file not found: '+src_manifest )

try:
    etparse = ET.parse( src_manifest )
except:
    parser.error( 'Cannot read Manifest' )

manifest = etparse.getroot()
if not manifest:
    parser.error( 'Cannot read Manifest' )

for elem in manifest.iter():
    # print( elem.attrib )
    elem.attrib = { k.replace('{http://schemas.android.com/apk/res/android}', ''): v for k, v in elem.attrib.items() }
    # print( elem.attrib )

source_path = 'src/' + os.path.dirname( manifest.attrib['package'].replace( '.', '/' ) )
source_fullpath = args.directory + '/' + source_path

if not os.path.isdir(source_fullpath):
    parser.error( 'source directory not found: '+source_fullpath )

if args.term:
    grep_term = args.term
else:
    grep_term = manifest.attrib['package'].split('.')[1]


tmp = manifest.attrib['package'].split('.')
package_name_short = tmp[0] + '.' + tmp[1]

t_templates = glob.glob( script_dir+'/_*')
t_templates_str = {}
loadTemplates()

t_activities = []
t_services = []
t_receivers = []
t_providers = []
t_parameters = []

t_datas = {}
t_datas['directory'] = args.directory
t_datas['date'] = datetime.datetime.today().strftime('%d/%m/%Y')
t_datas['build'] = getBuild()
t_datas['package_name'] = manifest.attrib['package']
t_datas['package_name_short'] = package_name_short
t_datas['source_path'] = source_path
t_datas['source_fullpath'] = source_fullpath
t_datas['permissions_created'], t_datas['permissions_used'], t_datas['permissions_required'] = listPermissions()
t_datas['files'] = listFiles(['/assets','/res/raw'])
t_datas['activities_manifest'] = listActivitiesManifest()
t_datas['activities_srcgrep'] = listActivitiesSourceGrep()
t_datas['receivers_manifest'] = listReceiversManifest()
t_datas['receivers_srcgrep'] = listReceiversSourceGrep()
t_datas['providers_manifest'] = listProvidersManifest()
t_datas['providers_srcgrep'] = listProvidersSourceGrep()
t_datas['providers_uris'] = getProvidersURIs()
t_datas['services_manifest'] = listServicesManifest()
t_datas['services_srcgrep'] = listServicesSourceGrep()
t_datas['intent_grep'] = doGrep('intent')
t_datas['external_call_grep'] = doGrep('external_call')
t_datas['webview_grep'] = doGrep('webview')
t_datas['internal_storage_grep'] = doGrep('internal_storage')
t_datas['external_storage_grep'] = doGrep('external_storage')
t_datas['log_grep'] = doGrep('log')
t_datas['slog_grep'] = doGrep('slog')
t_datas['event_log_grep'] = doGrep('event_log')
t_datas['timber_grep'] = doGrep('timber')
t_datas['certificate_grep'] = doGrep('certificate')
# t_datas['crypto_grep'] = doGrep('crypto')
t_datas['package_grep'] = doGrep('package')
t_datas['takeovers_grep'] = doGrep('takeovers')
t_datas['keys_grep'] = doGrep('keys')
t_datas['urls_grep'] = doGrep('urls')
t_datas['ips_grep'] = doGrep('ips')
t_datas['strings_grep'] = doGrep('strings')
t_datas['parameters_grep'] = doGrep('parameters')
t_datas['url_parameters_grep'] = doGrep('url_parameters')
t_datas['file_manipulation_grep'] = doGrep('file_manipulation')


report = renderTemplate( 'report', t_datas )
saveReport( report )

saveActivities()
saveReceivers()
saveProviders()
saveServices()
t_parameters = getParameters()
saveParameters()
