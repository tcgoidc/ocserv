if not readline_dep.found()
  # occtl requires readline or libedit
  subdir_done()
endif

occtl_sources = files(
  'occtl.c',
  'pager.c',
  'time.c',
  'cache.c',
  'ip-cache.c',
  'nl.c',
  'print.c',
  'json.c',
  'unix.c',
  'session-cache.c',
  'maxmind.c',
)

occtl_inc = [all_inc, include_directories('.')]

occtl_deps = [
  common_dep, ccan_dep, ipc_dep, protobuf_dep,
  gnutls_dep, nettle_dep,
  talloc_dep, readline_dep,
]

if libnl_dep.found()
  occtl_deps += libnl_dep
endif
occtl_c_args = []
if maxmind_dep.found()
  occtl_deps += maxmind_dep
  # 'auto' picks the DB-IP Lite database if installed, else the GeoLite2
  # one, else the DB-IP Lite name
  geo_candidates = {
    'country': ['dbip-country-lite.mmdb', 'GeoLite2-Country.mmdb'],
    'city': ['dbip-city-lite.mmdb', 'GeoLite2-City.mmdb'],
  }
  foreach db, names : geo_candidates
    path = get_option('maxminddb_location_' + db)
    if path == 'auto'
      path = '/usr/share/GeoIP/' + names[0]
      foreach name : names
        if fs.is_file('/usr/share/GeoIP/' + name)
          path = '/usr/share/GeoIP/' + name
          break
        endif
      endforeach
      message('occtl ' + db + ' database: ' + path)
    endif
    occtl_c_args += ['-DMAXMINDDB_LOCATION_' + db.to_upper() + '="' + path + '"']
  endforeach
endif

executable('occtl', occtl_sources,
  c_args: occtl_c_args,
  dependencies: occtl_deps,
  include_directories: occtl_inc,
  install: true,
  install_dir: get_option('bindir'),
)
