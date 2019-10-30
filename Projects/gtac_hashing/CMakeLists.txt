disable_rtti()

file(GLOB_RECURSE SOURCES *.cpp *.h)

if(MSVC)
	precompiled_header(pch)
endif()

new_library_shared(gtac_hashing "${SOURCES}" "")

# Link with CryptoPP
target_link_libraries(gtac_hashing cryptopp-static)

set_target_properties(gtac_hashing PROPERTIES FOLDER modules)
