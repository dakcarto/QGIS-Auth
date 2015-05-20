
// QGSCONFIG.H

#ifndef QGSCONFIG_H
#define QGSCONFIG_H

// Version must be specified according to
// <int>.<int>.<int>-<any text>.
// or else upgrading old project file will not work
// reliably.
#define VERSION "2.8.2-Wien"

//used in vim src/core/qgis.cpp
//The way below should work but it resolves to a number like 0110 which the compiler treats as octal I think
//because debuggin it out shows the decimal number 72 which results in incorrect version status.
//As a short term fix I (Tim) am defining the version in top level cmake. It would be good to 
//reinstate this more generic approach below at some point though
//#define VERSION_INT 281
#define VERSION_INT 20801
#define ABISYM(x) x ## 20801
//used in main.cpp and anywhere else where the release name is needed
#define RELEASE_NAME "Wien"

#define QGIS_PLUGIN_SUBDIR "../PlugIns/qgis"
#define QGIS_DATA_SUBDIR "../Resources"
#define QGIS_LIBEXEC_SUBDIR "lib/qgis"
#define QGIS_LIB_SUBDIR "lib"
#define CMAKE_INSTALL_PREFIX "/Users/larrys/QGIS/github.com/QGIS_APPS_boundless/QGIS.app/Contents/MacOS"
#define CMAKE_SOURCE_DIR "/Users/larrys/QGIS/github.com/QGIS-Boundless"

#define QSCINTILLA_VERSION_STR "2.8.4"

#if defined( __APPLE__ )
//used by Mac to find system or bundle resources relative to amount of bundling
#define QGIS_MACAPP_BUNDLE 0
#endif

#define QT_PLUGINS_DIR "/usr/local/Cellar/qt/4.8.6/plugins"
#define OSG_PLUGINS_PATH "/usr/local/lib/osgPlugins-3.2.0"

/* #undef USING_NMAKE */

#define HAVE_POSTGRESQL

#define HAVE_SPATIALITE

#define HAVE_MSSQL

/* #undef HAVE_ORACLE */

/* #undef HAVE_PYTHON */

/* #undef HAVE_TOUCH */

/* #undef HAVE_OSGEARTHQT */

/* #undef SERVER_SKIP_ECW */

#define HAVE_SERVER_PYTHON_PLUGINS

/* #undef ENABLE_MODELTEST */

#endif

