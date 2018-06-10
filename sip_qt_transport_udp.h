#pragma once

// 适配QT的sip transport层，具体参考sip_transport_udp.h/cpp的源码

#include "pj/types.h"
struct pjsip_endpoint;
struct pjsip_transport;
struct qt_sip_udp_transport;
/*
* @brief 启动一个pjsip的udp端口
* @param endpt pjsip对应的endpt
* @param port 需要启动的udp端口
* @param p_transport 返回的端口
*/
PJ_DECL(pj_status_t) qt_sip_transport_create(const int port, pjsip_endpoint* endpt, qt_sip_udp_transport** ptp);

/*
* @brief 销毁一个pjsip的udp端口
* @param endpt pjsip对应的endpt
* @param port 需要启动的udp端口
* @param p_transport 返回的端口
*/
void qt_sip_transport_destroy(qt_sip_udp_transport **tp);