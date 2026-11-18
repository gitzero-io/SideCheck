package com.bastionsecurity.sidecheck.engine.model

/**
 * What kind of device the report is for. Some permissions mean different things on each: a TV has
 * no reason to read text messages, while a phone's texting app needs to.
 */
enum class Platform { TV, PHONE }
