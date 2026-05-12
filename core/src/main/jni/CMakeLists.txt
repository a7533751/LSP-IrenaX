cmake_minimum_required(VERSION 3.28)
project(core)

add_subdirectory(${EXTERNAL_ROOT} external)

aux_source_directory(src SRC_LIST)
aux_source_directory(src/jni SRC_LIST)

add_library(${PROJECT_NAME} STATIC ${SRC_LIST})

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_compile_definitions(${PROJECT_NAME} PUBLIC LOG_DISABLED)

target_link_libraries(${PROJECT_NAME} PUBLIC dobby lsplant_static fmt-header-only)
target_link_libraries(${PROJECT_NAME} PRIVATE dex_builder_static)
