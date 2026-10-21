find_package(Threads REQUIRED)

foreach(example 02_params 03_json_schema 04_middleware)
    add_executable(trie_${example} ${example}.cc)
    target_link_libraries(trie_${example} PRIVATE trie::trie)
    target_compile_options(trie_${example} PRIVATE -fno-exceptions -fno-rtti)
endforeach()

add_executable(trie_01_hello 01_hello.cc)
target_link_libraries(trie_01_hello PRIVATE trie::trie Threads::Threads)
target_compile_options(trie_01_hello PRIVATE -fno-exceptions -fno-rtti)

add_executable(trie_05_client 05_client.cc)
target_link_libraries(trie_05_client PRIVATE trie::trie Threads::Threads)
target_compile_options(trie_05_client PRIVATE -fno-exceptions -fno-rtti)

add_executable(trie_06_threaded 06_threaded.cc)
target_link_libraries(trie_06_threaded PRIVATE trie::trie Threads::Threads)
target_compile_options(trie_06_threaded PRIVATE -fno-exceptions -fno-rtti)

add_executable(trie_basic basic.cc)
target_link_libraries(trie_basic PRIVATE trie::trie)
target_compile_options(trie_basic PRIVATE -fno-exceptions -fno-rtti)

add_executable(trie_http_server http_server.cc)
target_link_libraries(trie_http_server PRIVATE trie::trie)
target_compile_options(trie_http_server PRIVATE -fno-exceptions -fno-rtti)

find_package(SQLite3 QUIET)
if(TARGET SQLite3::SQLite3)
    set(TRIE_SQLITE_TARGET SQLite3::SQLite3)
elseif(TARGET SQLite::SQLite3)
    set(TRIE_SQLITE_TARGET SQLite::SQLite3)
endif()
if(SQLite3_FOUND)
    add_executable(trie_sqlite_notes sqlite_notes.cc)
    target_link_libraries(trie_sqlite_notes PRIVATE trie::trie ${TRIE_SQLITE_TARGET})
    target_compile_options(trie_sqlite_notes PRIVATE -fno-exceptions -fno-rtti)

    add_executable(trie_chat chat/chat_server.cc)
    target_link_libraries(trie_chat PRIVATE trie::trie ${TRIE_SQLITE_TARGET})
    target_compile_options(trie_chat PRIVATE -fno-exceptions -fno-rtti)
endif()
