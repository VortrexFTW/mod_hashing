disable_rtti()

INCLUDE_DIRECTORIES("../cryptopp")
LINK_DIRECTORIES("../cryptopp/lib/${ENGINE_PLATFORM}")

file(GLOB_RECURSE SOURCES *.cpp *.h)

if(MSVC)
	precompiled_header(pch)
endif()

new_library_shared(gtac_hashing "${SOURCES}" "")
if(WIN32)
target_link_libraries(gtac_hashing libcryptopp)
else()
target_link_libraries(gtac_hashing cryptopp)
endif()
set_target_properties(gtac_hashing PROPERTIES FOLDER Modules)
