#ifndef FLEXIO_API_WRAPPER_H_
#define FLEXIO_API_WRAPPER_H_

#include "flexio_api_ver.h"

#ifdef __DPA
#include <libflexio-dev/flexio_dev_ver.h>

#ifndef FLEXIO_DEV_VER_USED
#define FLEXIO_DEV_VER_USED FLEXIO_DEV_VER(LIB_FLEXIO_MAJOR_VERSION, LIB_FLEXIO_MINOR_VERSION, LIB_FLEXIO_PATCH_VERSION)
#endif
#include <libflexio-dev/flexio_dev.h>

#else

#include <libflexio/flexio_ver.h>

#ifndef FLEXIO_VER_USED
#define FLEXIO_VER_USED FLEXIO_VER(LIB_FLEXIO_MAJOR_VERSION, LIB_FLEXIO_MINOR_VERSION, LIB_FLEXIO_PATCH_VERSION)
#endif

#include <libflexio/flexio.h>

#endif

#endif
