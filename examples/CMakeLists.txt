add_executable(trie_basic basic.cc)
target_link_libraries(trie_basic PRIVATE trie::trie)
target_compile_options(trie_basic PRIVATE -fno-exceptions -fno-rtti)

add_executable(trie_http_server http_server.cc)
target_link_libraries(trie_http_server PRIVATE trie::trie)
target_compile_options(trie_http_server PRIVATE -fno-exceptions -fno-rtti)
