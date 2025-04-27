import 'dart:convert';
import 'package:dio/dio.dart';
import '../security/security_manager.dart';
import '../utils/secure_logger.dart';
import 'dio_client.dart';

class NetworkService {
  final DioClient _dioClient;
  final SecurityManager _securityManager;
  final SecureLogger _logger;

  NetworkService(this._dioClient, this._securityManager, this._logger);

  Future<T> get<T>({
    required String endpoint,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
    required T Function(dynamic) converter,
  }) async {
    try {
      // التحقق من صحة الطلب
      final isValid = await _securityManager.validateRequest(
        path: endpoint,
        params: queryParameters ?? {},
        method: 'GET',
      );

      if (!isValid) {
        throw SecurityException('Invalid request');
      }

      // تشفير المعاملات
      final secureParams = queryParameters != null
          ? await _securityManager.prepareSecureRequest(queryParameters)
          : null;

      // إنشاء خيارات الطلب
      final secureOptions = options ?? Options();
      secureOptions.headers = {
        ...secureOptions.headers ?? {},
        'X-Request-ID': DateTime.now().millisecondsSinceEpoch.toString(),
        'X-Client-Version': '1.0.0',
      };

      // إرسال الطلب
      final response = await _dioClient.dio.get(
        endpoint,
        queryParameters: secureParams,
        options: secureOptions,
        cancelToken: cancelToken,
      );

      // التحقق من صحة الاستجابة
      final secureResponse = await _securityManager.processSecureResponse(response.data);

      return converter(secureResponse);
    } catch (e) {
      _logger.log(
        'Network GET request failed: $e',
        level: LogLevel.error,
        category: SecurityCategory.security,
      );
      rethrow;
    }
  }

  Future<T> post<T>({
    required String endpoint,
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
    required T Function(dynamic) converter,
  }) async {
    try {
      // التحقق من صحة الطلب
      final isValid = await _securityManager.validateRequest(
        path: endpoint,
        params: data is Map<String, dynamic> ? data : {},
        method: 'POST',
      );

      if (!isValid) {
        throw SecurityException('Invalid request');
      }

      // تشفير البيانات
      final secureData = data != null
          ? await _securityManager.prepareSecureRequest(
        data is Map<String, dynamic> ? data : {'data': data},
      )
          : null;

      // إنشاء خيارات الطلب
      final secureOptions = options ?? Options();
      secureOptions.headers = {
        ...secureOptions.headers ?? {},
        'X-Request-ID': DateTime.now().millisecondsSinceEpoch.toString(),
        'X-Client-Version': '1.0.0',
        'Content-Type': 'application/json',
      };

      // إرسال الطلب
      final response = await _dioClient.dio.post(
        endpoint,
        data: secureData,
        queryParameters: queryParameters,
        options: secureOptions,
        cancelToken: cancelToken,
      );

      // التحقق من صحة الاستجابة
      final secureResponse = await _securityManager.processSecureResponse(response.data);

      return converter(secureResponse);
    } catch (e) {
      _logger.log(
        'Network POST request failed: $e',
        level: LogLevel.error,
        category: SecurityCategory.security,
      );
      rethrow;
    }
  }

  Future<T> put<T>({
    required String endpoint,
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
    required T Function(dynamic) converter,
  }) async {
    try {
      // التحقق من صحة الطلب
      final isValid = await _securityManager.validateRequest(
        path: endpoint,
        params: data is Map<String, dynamic> ? data : {},
        method: 'PUT',
      );

      if (!isValid) {
        throw SecurityException('Invalid request');
      }

      // تشفير البيانات
      final secureData = data != null
          ? await _securityManager.prepareSecureRequest(
        data is Map<String, dynamic> ? data : {'data': data},
      )
          : null;

      // إنشاء خيارات الطلب
      final secureOptions = options ?? Options();
      secureOptions.headers = {
        ...secureOptions.headers ?? {},
        'X-Request-ID': DateTime.now().millisecondsSinceEpoch.toString(),
        'X-Client-Version': '1.0.0',
        'Content-Type': 'application/json',
      };

      // إرسال الطلب
      final response = await _dioClient.dio.put(
        endpoint,
        data: secureData,
        queryParameters: queryParameters,
        options: secureOptions,
        cancelToken: cancelToken,
      );

      // التحقق من صحة الاستجابة
      final secureResponse = await _securityManager.processSecureResponse(response.data);

      return converter(secureResponse);
    } catch (e) {
      _logger.log(
        'Network PUT request failed: $e',
        level: LogLevel.error,
        category: SecurityCategory.security,
      );
      rethrow;
    }
  }

  Future<T> delete<T>({
    required String endpoint,
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
    required T Function(dynamic) converter,
  }) async {
    try {
      // التحقق من صحة الطلب
      final isValid = await _securityManager.validateRequest(
        path: endpoint,
        params: queryParameters ?? {},
        method: 'DELETE',
      );

      if (!isValid) {
        throw SecurityException('Invalid request');
      }

      // إنشاء خيارات الطلب
      final secureOptions = options ?? Options();
      secureOptions.headers = {
        ...secureOptions.headers ?? {},
        'X-Request-ID': DateTime.now().millisecondsSinceEpoch.toString(),
        'X-Client-Version': '1.0.0',
      };

      // إرسال الطلب
      final response = await _dioClient.dio.delete(
        endpoint,
        data: data,
        queryParameters: queryParameters,
        options: secureOptions,
        cancelToken: cancelToken,
      );

      // التحقق من صحة الاستجابة
      final secureResponse = await _securityManager.processSecureResponse(response.data);

      return converter(secureResponse);
    } catch (e) {
      _logger.log(
        'Network DELETE request failed: $e',
        level: LogLevel.error,
        category: SecurityCategory.security,
      );
      rethrow;
    }
  }

  Future<Response> download({
    required String urlPath,
    required String savePath,
    ProgressCallback? onReceiveProgress,
    Map<String, dynamic>? queryParameters,
    CancelToken? cancelToken,
    bool deleteOnError = true,
    String lengthHeader = Headers.contentLengthHeader,
    dynamic data,
    Options? options,
  }) async {
    try {
      // التحقق من صحة المسار
      if (!await _securityManager._validatePath(savePath)) {
        throw SecurityException('Invalid save path');
      }

      // إنشاء خيارات الطلب
      final secureOptions = options ?? Options();
      secureOptions.responseType = ResponseType.stream;
      secureOptions.headers = {
        ...secureOptions.headers ?? {},
        'X-Request-ID': DateTime.now().millisecondsSinceEpoch.toString(),
      };

      // إرسال الطلب
      final response = await _dioClient.dio.download(
        urlPath,
        savePath,
        onReceiveProgress: onReceiveProgress,
        queryParameters: queryParameters,
        cancelToken: cancelToken,
        deleteOnError: deleteOnError,
        lengthHeader: lengthHeader,
        data: data,
        options: secureOptions,
      );

      return response;
    } catch (e) {
      _logger.log(
        'Download failed: $e',
        level: LogLevel.error,
        category: SecurityCategory.security,
      );
      rethrow;
    }
  }

  Future<Response> upload({
    required String endpoint,
    required String filePath,
    String? fileName,
    Map<String, dynamic>? data,
    ProgressCallback? onSendProgress,
    CancelToken? cancelToken,
    Options? options,
  }) async {
    try {
      // التحقق من صحة المسار
      if (!await _securityManager.validatePath(filePath)) {
        throw SecurityException('Invalid file path');
      }

      // إنشاء FormData
      final formData = FormData.fromMap({
        ...?data,
        'file': await MultipartFile.fromFile(
          filePath,
          filename: fileName,
        ),
      });

      // إنشاء خيارات الطلب
      final secureOptions = options ?? Options();
      secureOptions.headers = {
        ...secureOptions.headers ?? {},
        'X-Request-ID': DateTime.now().millisecondsSinceEpoch.toString(),
        'Content-Type': 'multipart/form-data',
      };

      // إرسال الطلب
      final response = await _dioClient.dio.post(
        endpoint,
        data: formData,
        onSendProgress: onSendProgress,
        cancelToken: cancelToken,
        options: secureOptions,
      );

      return response;
    } catch (e) {
      _logger.log(
        'Upload failed: $e',
        level: LogLevel.error,
        category: SecurityCategory.security,
      );
      rethrow;
    }
  }
}

// استثناءات الشبكة المخصصة
class NetworkException implements Exception {
  final String message;
  final int? statusCode;
  final dynamic data;

  NetworkException(this.message, {this.statusCode, this.data});

  @override
  String toString() => 'NetworkException: $message ${statusCode != null ? '($statusCode)' : ''}';
}

class TimeoutException extends NetworkException {
  TimeoutException() : super('Request timed out');
}

class NoInternetException extends NetworkException {
  NoInternetException() : super('No internet connection');
}

class ServerException extends NetworkException {
  ServerException(String message, {int? statusCode}) : super(message, statusCode: statusCode);
}

class UnauthorizedException extends NetworkException {
  UnauthorizedException() : super('Unauthorized', statusCode: 401);
}

class ForbiddenException extends NetworkException {
  ForbiddenException() : super('Forbidden', statusCode: 403);
}

class NotFoundException extends NetworkException {
  NotFoundException() : super('Not found', statusCode: 404);
}

class RateLimitException extends NetworkException {
  RateLimitException() : super('Rate limit exceeded', statusCode: 429);
}

class SecurityViolationException extends NetworkException {
  SecurityViolationException(String message) : super(message);
}