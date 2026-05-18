# SQLite3 amalgamation (vendored locally).
set(SQLITE_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/sqlite-amalgamation-3460100")

add_library(sqlite3 STATIC ${SQLITE_SRC_DIR}/sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${SQLITE_SRC_DIR})
target_compile_definitions(sqlite3 PUBLIC
    SQLITE_ENABLE_FTS5
    SQLITE_ENABLE_JSON1
    SQLITE_THREADSAFE=1
    SQLITE_DEFAULT_FOREIGN_KEYS=1
    SQLITE_DQS=0
)
if(NOT WIN32)
    target_link_libraries(sqlite3 PUBLIC dl m)
endif()
add_library(sqlite3::sqlite3 ALIAS sqlite3)
