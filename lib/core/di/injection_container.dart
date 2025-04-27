import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:get_it/get_it.dart';
import 'package:local_auth/local_auth.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

// Core
import '../constants/api_constants.dart';
import '../network/dio_client.dart';
import '../network/network_service.dart';
import '../security/security_manager.dart';
import '../security/encryption_service.dart';
import '../security/secure_storage_service.dart';
import '../security/root_detection_service.dart';
import '../security/ssl_pinning_service.dart';
import '../security/screenshot_prevention_service.dart';
import '../security/anti_tampering_service.dart';
import '../security/package_validation_service.dart';
import '../security/rate_limiter_service.dart';
import '../security/nonce_generator_service.dart';
import '../security/obfuscation_service.dart';
import '../security/token_manager.dart';
import '../utils/device_info_service.dart';
import '../utils/environment_checker.dart';
import '../utils/file_path_validator.dart';
import '../utils/input_sanitizer.dart';
import '../utils/integrity_checker.dart';
import '../utils/key_generator_service.dart';
import '../utils/secure_logger.dart';
import '../utils/session_manager.dart';
import '../utils/time_manager.dart';

// Features
import '../../features/auth/data/datasources/auth_local_datasource.dart';
import '../../features/auth/data/datasources/auth_remote_datasource.dart';
import '../../features/auth/data/repositories/auth_repository_impl.dart';
import '../../features/auth/domain/repositories/auth_repository.dart';
import '../../features/auth/domain/usecases/login_usecase.dart';
import '../../features/auth/domain/usecases/signup_usecase.dart';
import '../../features/auth/domain/usecases/logout_usecase.dart';
import '../../features/auth/domain/usecases/refresh_token_usecase.dart';
import '../../features/auth/domain/usecases/biometric_auth_usecase.dart';
import '../../features/auth/presentation/bloc/auth_bloc.dart';

import '../../features/home/data/datasources/unsplash_datasource.dart';
import '../../features/home/data/repositories/photo_repository_impl.dart';
import '../../features/home/domain/repositories/photo_repository.dart';
import '../../features/home/domain/usecases/get_photos_usecase.dart';
import '../../features/home/domain/usecases/search_photos_usecase.dart';
import '../../features/home/presentation/bloc/home_bloc.dart';

import '../../features/search/data/repositories/search_repository_impl.dart';
import '../../features/search/domain/repositories/search_repository.dart';
import '../../features/search/domain/usecases/search_photos_usecase.dart' as search;
import '../../features/search/presentation/bloc/search_bloc.dart';

final sl = GetIt.instance;

Future<void> init() async {
  // External
  final sharedPreferences = await SharedPreferences.getInstance();
  sl.registerLazySingleton(() => sharedPreferences);
  sl.registerLazySingleton(() => const FlutterSecureStorage());
  sl.registerLazySingleton(() => Dio());
  sl.registerLazySingleton(() => Connectivity());
  sl.registerLazySingleton(() => LocalAuthentication());

  // Get package info
  final packageInfo = await PackageInfo.fromPlatform();
  sl.registerLazySingleton(() => packageInfo);

  // Core - Network
  sl.registerLazySingleton(() => DioClient(
    dio: sl(),
    interceptors: [
      // Add interceptors as needed
    ],
  ));

  sl.registerLazySingleton<NetworkService>(() => NetworkServiceImpl(
    dioClient: sl(),
    securityManager: sl(),
  ));

  sl.registerLazySingleton<NetworkInfo>(() => NetworkInfoImpl(sl()));

  // Core - Security
  sl.registerLazySingleton(() => EncryptionService());
  sl.registerLazySingleton(() => SecureStorageService(storage: sl()));
  sl.registerLazySingleton(() => RootDetectionService());
  sl.registerLazySingleton(() => SSLPinningService());
  sl.registerLazySingleton(() => ScreenshotPreventionService());
  sl.registerLazySingleton(() => AntiTamperingService(packageInfo: sl()));
  sl.registerLazySingleton(() => PackageValidationService(packageInfo: sl()));
  sl.registerLazySingleton(() => RateLimiterService());
  sl.registerLazySingleton(() => NonceGeneratorService());
  sl.registerLazySingleton(() => ObfuscationService());
  sl.registerLazySingleton(() => TokenManager(
    secureStorage: sl(),
    encryptionService: sl(),
  ));

  sl.registerLazySingleton(() => SecurityManager(
    rootDetectionService: sl(),
    antiTamperingService: sl(),
    packageValidationService: sl(),
    environmentChecker: sl(),
    integrityChecker: sl(),
    sslPinningService: sl(),
    screenshotPreventionService: sl(),
    secureLogger: sl(),
  ));

  // Core - Utils
  sl.registerLazySingleton(() => DeviceInfoService());
  sl.registerLazySingleton(() => EnvironmentChecker());
  sl.registerLazySingleton(() => FilePathValidator());
  sl.registerLazySingleton(() => InputSanitizer());
  sl.registerLazySingleton(() => IntegrityChecker());
  sl.registerLazySingleton(() => KeyGeneratorService());
  sl.registerLazySingleton(() => SecureLogger(
    obfuscationService: sl(),
    environmentChecker: sl(),
  ));
  sl.registerLazySingleton(() => SessionManager(
    secureStorage: sl(),
    timeManager: sl(),
  ));
  sl.registerLazySingleton(() => TimeManager());

  // Features - Auth
  // Data sources
  sl.registerLazySingleton<AuthLocalDataSource>(() => AuthLocalDataSourceImpl(
    secureStorage: sl(),
    encryptionService: sl(),
  ));

  sl.registerLazySingleton<AuthRemoteDataSource>(() => AuthRemoteDataSourceImpl(
    networkService: sl(),
  ));

  // Repository
  sl.registerLazySingleton<AuthRepository>(() => AuthRepositoryImpl(
    remoteDataSource: sl(),
    localDataSource: sl(),
    networkInfo: sl(),
    deviceInfo: sl(),
  ));

  // Use cases
  sl.registerLazySingleton(() => LoginUseCase(sl()));
  sl.registerLazySingleton(() => SignUpUseCase(sl()));
  sl.registerLazySingleton(() => LogoutUseCase(sl()));
  sl.registerLazySingleton(() => RefreshTokenUseCase(sl()));
  sl.registerLazySingleton(() => BiometricAuthUseCase(sl()));

  // Bloc
  sl.registerFactory(() => AuthBloc(
    loginUseCase: sl(),
    signUpUseCase: sl(),
    logoutUseCase: sl(),
    refreshTokenUseCase: sl(),
    biometricAuthUseCase: sl(),
    sessionManager: sl(),
  ));

  // Features - Home
  // Data sources
  sl.registerLazySingleton<UnsplashDataSource>(() => UnsplashDataSourceImpl(
    networkService: sl(),
  ));

  // Repository
  sl.registerLazySingleton<PhotoRepository>(() => PhotoRepositoryImpl(
    dataSource: sl(),
    networkInfo: sl(),
  ));

  // Use cases
  sl.registerLazySingleton(() => GetPhotosUseCase(sl()));
  sl.registerLazySingleton(() => SearchPhotosUseCase(sl()));

  // Bloc
  sl.registerFactory(() => HomeBloc(
    getPhotosUseCase: sl(),
    searchPhotosUseCase: sl(),
  ));

  // Features - Search
  // Repository
  sl.registerLazySingleton<SearchRepository>(() => SearchRepositoryImpl(
    dataSource: sl(),
    networkInfo: sl(),
    secureStorage: sl(),
  ));

  // Use cases
  sl.registerLazySingleton(() => search.SearchPhotosUseCase(sl()));
  sl.registerLazySingleton(() => search.GetSearchSuggestionsUseCase(sl()));
  sl.registerLazySingleton(() => search.GetSearchHistoryUseCase(sl()));
  sl.registerLazySingleton(() => search.ClearSearchHistoryUseCase(sl()));

  // Bloc
  sl.registerFactory(() => SearchBloc(
    searchPhotosUseCase: sl(),
    getSearchSuggestionsUseCase: sl(),
    getSearchHistoryUseCase: sl(),
    clearSearchHistoryUseCase: sl(),
  ));
}