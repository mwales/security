cmake_minimum_required(VERSION 3.9.1)

project(FindFloats)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt5Widgets)

set(${PROJECT_NAME}_SRC
  DecodedValue.cpp
  MainWindow.cpp
  MainWindow.ui
  main.cpp
)
add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SRC} )
target_link_libraries(${PROJECT_NAME} Qt5::Widgets)
