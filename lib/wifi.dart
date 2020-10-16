import 'dart:async';

import 'package:flutter/services.dart';

enum WifiState { error, success, already }

class Wifi {
  static final String TIME_OUT = "TIME_OUT";
  static final String WIFI_MANAGER_IS_NULL = "WIFI_MANAGER_IS_NULL";
  static final String SDK_LEVEL_TOO_LOW = "SDK_LEVEL_TOO_LOW";
  
  static const MethodChannel _channel = const MethodChannel(
      'plugins.ly.com/wifi');

  static Future<String> get ssid async {
    return await _channel.invokeMethod('ssid');
  }

  static Future<int> get level async {
    return await _channel.invokeMethod('level');
  }

  static Future<String> get ip async {
    return await _channel.invokeMethod('ip');
  }

  static Future<dynamic> get is5G async {
    try{
      return await _channel.invokeMethod('is5G');
    } on PlatformException catch(e){
      return e;
    }
  }

  static Future<dynamic> list(String key) async {
    final Map<String, dynamic> params = {
      'key': key,
    };
    try {
      var results = await _channel.invokeMethod('list', params);
      List<WifiResult> resultList = [];
      for (int i = 0; i < results.length; i++) {
        resultList.add(WifiResult(
            results[i]['ssid'], results[i]['level'], results[i]['5G']));
      }
      return resultList;
    } on PlatformException catch (e) {
      return e;
    }
  }

  static Future<WifiState> connection(String ssid, String password) async {
    final Map<String, dynamic> params = {
      'ssid': ssid,
      'password': password,
    };
    int state = await _channel.invokeMethod('connection', params);
    switch (state) {
      case 0:
        return WifiState.error;
      case 1:
        return WifiState.success;
      case 2:
        return WifiState.already;
      default:
        return WifiState.error;
    }
  }

}

class WifiResult {
  String ssid;
  int level;
  bool is5G;

  WifiResult(this.ssid, this.level, this.is5G);
}
