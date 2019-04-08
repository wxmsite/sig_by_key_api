file(GLOB HEADERS "include/steem/plugins/sig_by_key_api/*.hpp")
file(GLOB HEADERS "include/steem/plugins/sig_by_key_api/*.h")
add_library( sig_by_key_api_plugin
        sig_by_key_api.cpp
        relic_api.cpp
        )

# 当该模块调用了其他模块的方法时，target_link_libraries需要将这些被调用的模块添加进来。
# 下面的例子基本上是最小模块
target_link_libraries( sig_by_key_api_plugin json_rpc_plugin steem_protocol appbase fc relic ${CMAKE_THREAD_LIBS_INIT})
target_include_directories( sig_by_key_api_plugin PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}
    /usr/local/include
    /usr/include
    include
)
link_directories(
    ${PROJECT_BINARY_DIR}/lib
    /usr/local/lib
    /usr/lib
)

if( CLANG_TIDY_EXE )
    set_target_properties(
            sig_by_key_api_plugin PROPERTIES
            CXX_CLANG_TIDY "${DO_CLANG_TIDY}"
    )
endif( CLANG_TIDY_EXE )

install( TARGETS
        sig_by_key_api_plugin

        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        )