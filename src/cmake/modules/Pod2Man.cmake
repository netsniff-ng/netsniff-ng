#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2012 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# Generate man pages of the project by using the
# POD header written in the tool source code.
# To use it, include this file in CMakeLists.txt and
# invoke POD2MAN(<podfile> <manfile> <section>)

MACRO(POD2MAN PODFILE MANFILE SECTION)
	FIND_PROGRAM(POD2MAN pod2man)
	FIND_PROGRAM(GZIP gzip)

	IF(NOT POD2MAN)
		MESSAGE(FATAL ERROR "Need pod2man installed to generate man page")
	ENDIF(NOT POD2MAN)

	IF(NOT GZIP)
		MESSAGE(FATAL ERROR "Need gzip installed to compress man page")
	ENDIF(NOT GZIP)

	IF(NOT EXISTS ${PODFILE})
		MESSAGE(FATAL ERROR "Could not find pod file ${PODFILE} to generate man page")
	ENDIF(NOT EXISTS ${PODFILE})

	ADD_CUSTOM_COMMAND(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${MANFILE}.${SECTION}
		DEPENDS ${PODFILE}
		COMMAND ${POD2MAN}
		ARGS --section ${SECTION} --center ${CMAKE_PROJECT_NAME} --release --stderr --name ${MANFILE}
		${PODFILE} > ${CMAKE_CURRENT_BINARY_DIR}/${MANFILE}.${SECTION}
	)

	ADD_CUSTOM_COMMAND(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${MANFILE}.${SECTION}.gz
		COMMAND ${GZIP} -c ${CMAKE_CURRENT_BINARY_DIR}/${MANFILE}.${SECTION} > ${CMAKE_CURRENT_BINARY_DIR}/${MANFILE}.${SECTION}.gz
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${MANFILE}.${SECTION}
	)

	SET(MANPAGE_TARGET "man-${MANFILE}")

	ADD_CUSTOM_TARGET(${MANPAGE_TARGET} DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${MANFILE}.${SECTION}.gz)
	ADD_DEPENDENCIES(man ${MANPAGE_TARGET})

	INSTALL(
		FILES ${CMAKE_CURRENT_BINARY_DIR}/${MANFILE}.${SECTION}.gz
		DESTINATION share/man/man${SECTION}
    	)
ENDMACRO(POD2MAN PODFILE MANFILE SECTION)

MACRO(ADD_MANPAGE_TARGET)
	# It is not possible add a dependency to target 'install'
	# Run hard-coded 'make man' when 'make install' is invoked
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND make man)")
	ADD_CUSTOM_TARGET(man)
ENDMACRO(ADD_MANPAGE_TARGET)
