import 'package:get_it/get_it.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:dio/dio.dart';
import '../security/security_manager.dart';
import '../security/encryption_service.dart';
import '../security/ssl_pinning_service.dart';
import '../security/root_detection_service.dart';
import '../security/screenshot_prevention_service.dart';
import '../security/secure_storage_service.dart';
import '../security/token_manager.dart';
import '../security/anti_tampering_service.dart';
import '../security/rate_limiter_service.dart';
import '../security/obfuscation_service.dart';
import '../security/nonce_generator_service.dart';
import '../security/package_validation_service.dart';
import '../network/dio_client.dart';
import '../network/network_service.dart';
import '../network/interceptors/auth_interceptor.dart';
import '../network/interceptors/error_interceptor.dart';
import '../network/interceptors/logging_interceptor.dart';
import '../network/interceptors/encryption_interceptor.dart';
import '../network/interceptors/security_interceptor.dart';
import '../network/certificate_pinning/certificate_manager.dart';
import '../network/certificate_pinning/public_key_store.dart';
import '../utils/validators.dart';
import '../utils/input_sanitizer.dart';
import '../utils/file_path_validator.dart';
import '../utils/secure_logger.dart';
import '../utils/device_info_service.dart';
import '../utils/environment_checker.dart';
import '../utils/session_manager.dart';
import '../utils/key_generator_service.dart';
import '../utils/time_manager.dart';
import '../utils/integrity_checker.dart';
import '../../features/auth/data/datasources/auth_remote_datasource.dart';
import '../../features/auth/data/datasources/auth_local_datasource.dart';
import '../../features/auth/data/repositories/auth_repository_impl.dart';
import '../../features/auth/domain/repositories/auth_repository.dart';
import '../../features/auth/domain/usecases/login_usecase.dart';
import '../../features/auth/domain/usecases/signup_usecase.dart';
import '../../features/auth/domain/usecases/logout_usecase.dart';
import '../../features/auth/domain/usecases/biometric_auth_usecase.dart';
import '../../features/auth/domain/usecases/refresh_token_usecase.dart';
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
  // Core Security Services
  sl.registerLazySingleton(() => SecureLogger());

  sl.registerLazySingleton(() => SecureStorageService(sl()));
  sl.registerLazySingleton(() => EncryptionService(sl(), sl()));
  sl.registerLazySingleton(() => SSLPinningService(sl(), sl()));
  sl.registerLazySingleton(() => RootDetectionService(sl(), sl()));
  sl.registerLazySingleton(() => ScreenshotPreventionService(sl()));
  sl.registerLazySingleton(() => AntiTamperingService(sl(), sl(), sl()));
  sl.registerLazySingleton(() => RateLimiterService(sl(), sl(), sl()));
  sl.registerLazySingleton(() => ObfuscationService(sl()));
  sl.registerLazySingleton(() => NonceGeneratorService());
  sl.registerLazySingleton(() => PackageValidationService(sl()));

  // Token Management
  sl.registerLazySingleton(() => TokenManager(sl(), sl(), sl(), sl()));

  // Managers
  sl.registerLazySingleton(() => SecurityManager(
      sl(), sl(), sl(), sl(), sl(), sl(), sl(), sl(), sl(), sl(), sl(), sl(), sl()
  ));

  // Utils
  sl.registerLazySingleton(() => Validators());
  sl.registerLazySingleton(() => InputSanitizer());
  sl.registerLazySingleton(() => FilePathValidator());
  sl.registerLazySingleton(() => DeviceInfoService());
  sl.registerLazySingleton(() => EnvironmentChecker(sl()));
  sl.registerLazySingleton(() => SessionManager(sl(), sl()));
  sl.registerLazySingleton(() => KeyGeneratorService());
  sl.registerLazySingleton(() => TimeManager());
  sl.registerLazySingleton(() => IntegrityChecker(sl()));

  // Network
  sl.registerLazySingleton(() => CertificateManager(sl()));
  sl.registerLazySingleton(() => PublicKeyStore(sl()));

  // Interceptors
  sl.registerLazySingleton(() => AuthInterceptor(sl(), sl()));
  sl.registerLazySingleton(() => ErrorInterceptor(sl()));
  sl.registerLazySingleton(() => LoggingInterceptor(sl()));
  sl.registerLazySingleton(() => EncryptionInterceptor(sl(), sl()));
  sl.registerLazySingleton(() => SecurityInterceptor(sl(), sl()));

  // Dio Client
  sl.registerLazySingleton(() => Dio());
  sl.registerLazySingleton(() => DioClient(
    sl(),
    sslPinningService: sl(),
    authInterceptor: sl(),
    errorInterceptor: sl(),
    loggingInterceptor: sl(),
    encryptionInterceptor: sl(),
    securityInterceptor: sl(),
  ));

  sl.registerLazySingleton(() => NetworkService(sl(), sl()));

  // Auth Feature
  // Data sources
  sl.registerLazySingleton<AuthRemoteDataSource>(
        () => AuthRemoteDataSourceImpl(sl(), sl()),
  );
  sl.registerLazySingleton<AuthLocalDataSource>(
        () => AuthLocalDataSourceImpl(sl(), sl(), sl()),
  );

  // Repository
  sl.registerLazySingleton<AuthRepository>(
        () => AuthRepositoryImpl(sl(), sl(), sl()),
  );

  // Use cases
  sl.registerLazySingleton(() => LoginUseCase(sl()));
  sl.registerLazySingleton(() => SignupUseCase(sl()));
  sl.registerLazySingleton(() => LogoutUseCase(sl()));
  sl.registerLazySingleton(() => BiometricAuthUseCase(sl()));
  sl.registerLazySingleton(() => RefreshTokenUseCase(sl()));

  // Bloc
  sl.registerFactory(() => AuthBloc(
    loginUseCase: sl(),
    signupUseCase: sl(),
    logoutUseCase: sl(),
    biometricAuthUseCase: sl(),
    refreshTokenUseCase: sl(),
    securityManager: sl(),
    tokenManager: sl(),
  ));

  // Home Feature
  // Data sources
  sl.registerLazySingleton<UnsplashDataSource>(
        () => UnsplashDataSourceImpl(sl(), sl()),
  );

  // Repository
  sl.registerLazySingleton<PhotoRepository>(
        () => PhotoRepositoryImpl(sl(), sl()),
  );

  // Use cases
  sl.registerLazySingleton(() => GetPhotosUseCase(sl()));
  sl.registerLazySingleton(() => SearchPhotosUseCase(sl()));

  // Bloc
  sl.registerFactory(() => HomeBloc(
    getPhotosUseCase: sl(),
    securityManager: sl(),
  ));

  // Search Feature
  // Repository
  sl.registerLazySingleton<SearchRepository>(
        () => SearchRepositoryImpl(sl(), sl()),
  );

  // Use cases
  sl.registerLazySingleton(() => search.SearchPhotosUseCase(sl()));

  // Bloc
  sl.registerFactory(() => SearchBloc(
    searchPhotosUseCase: sl(),
    securityManager: sl(),
  ));

  // External
  sl.registerLazySingleton(() => const FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: true,
    ),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
    ),
  ));
}

// Security Module - for more complex injection scenarios
class SecurityModule {
  static Future<void> configureSecureInjection() async {
    // Additional secure configuration
    await _configureSecureStorage();
    await _configureNetworkSecurity();
    await _configureCryptography();
  }

  static Future<void> _configureSecureStorage() async {
    // Initialize secure storage with custom config
    final secureStorage = sl<SecureStorageService>();
    await secureStorage.initialize();
  }

  static Future<void> _configureNetworkSecurity() async {
    // Initialize SSL pinning
    final sslPinning = sl<SSLPinningService>();
    await sslPinning.initialize();

    // Initialize certificate management
    final certManager = sl<CertificateManager>();
    await certManager.loadCertificates();
  }

  static Future<void> _configureCryptography() async {
    // Initialize encryption service
    final encryption = sl<EncryptionService>();
    await encryption.initialize();

    // Initialize key management
    final keyGenerator = sl<KeyGeneratorService>();
    await keyGenerator.initialize();
  }
}

// Test Module - for testing purposes only
class TestModule {
  static void configureMockInjection() {
    // Configure mock dependencies for testing
    // This should only be used in test environment
  }
}

// Clean up function
Future<void> resetDependencies() async {
  await sl.reset();
}