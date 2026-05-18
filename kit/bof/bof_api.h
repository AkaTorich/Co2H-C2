// bof_api.h — обратная совместимость: просто включает beacon.h.
//
// Все Co2H BOF теперь используют единый beacon.h с полным CS 4.12 API.
// Этот файл оставлен чтобы существующие #include "bof_api.h" не ломались.

#ifndef BOF_API_H
#define BOF_API_H

#include "beacon.h"
#include <shellapi.h>

#endif // BOF_API_H
