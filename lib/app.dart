import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'core/security/security_manager.dart';
import 'core/security/screenshot_prevention_service.dart';
import 'core/di/injection_container.dart' as di;
import 'core/utils/secure_logger.dart';
import 'features/auth/presentation/pages/login_page.dart';
import 'features/auth/presentation/pages/signup_page.dart';
import 'features/home/presentation/pages/home_page.dart';
import 'features/search/presentation/pages/search_page.dart';

class SecureApp extends StatefulWidget {
  const SecureApp({Key? key}) : super(key: key);

  @override
  State<SecureApp> createState() => _SecureAppState();
}

class _SecureAppState extends State<SecureApp> with WidgetsBindingObserver {
  late final SecurityManager _securityManager;
  late final SecureLogger _logger;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _securityManager = di.sl<SecurityManager>();
    _logger = di.sl<SecureLogger>();

    // إعداد الأمان للتطبيق بالكامل
    _setupAppSecurity();
  }

  Future<void> _setupAppSecurity() async {
    // تعطيل خاصية النسخ/اللصق في التطبيق بالكامل
    SystemChannels.platform.setMethodCallHandler((call) async {
      if (call.method == 'TextInput.updateConfig') {
        final args = call.arguments as Map<dynamic, dynamic>;
        if (args['inputAction'] == 'TextInputAction.copy' ||
            args['inputAction'] == 'TextInputAction.cut' ||
            args['inputAction'] == 'TextInputAction.paste') {
          _logger.log(
            'Clipboard operation blocked',
            level: LogLevel.warning,
            category: SecurityCategory.security,
          );
          return null;
        }
      }
      return null;
    });

    // تطبيق سياسة المهلة
    SystemChannels.lifecycle.setMessageHandler((msg) async {
      if (msg == AppLifecycleState.resumed.toString()) {
        await _securityManager.performSecurityCheck();
      }
      return null;
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);

    switch (state) {
      case AppLifecycleState.resumed:
        _logger.log(
          'App resumed',
          level: LogLevel.info,
          category: SecurityCategory.session,
        );
        _securityManager.updateLastActivity();
        break;
      case AppLifecycleState.paused:
        _logger.log(
          'App paused',
          level: LogLevel.info,
          category: SecurityCategory.session,
        );
        break;
      case AppLifecycleState.inactive:
        _logger.log(
          'App inactive',
          level: LogLevel.info,
          category: SecurityCategory.session,
        );
        break;
      case AppLifecycleState.detached:
        _logger.log(
          'App detached',
          level: LogLevel.info,
          category: SecurityCategory.session,
        );
        break;
      case AppLifecycleState.hidden:
        _logger.log(
          'App hidden',
          level: LogLevel.info,
          category: SecurityCategory.session,
        );
        break;
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // منع تغيير حجم النص
    return MediaQuery(
      data: MediaQuery.of(context).copyWith(textScaleFactor: 1.0),
      child: MaterialApp(
        title: 'Secure App',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          primarySwatch: Colors.blue,
          visualDensity: VisualDensity.adaptivePlatformDensity,
          // تطبيق ثيم آمن
          appBarTheme: const AppBarTheme(
            elevation: 0,
            systemOverlayStyle: SystemUiOverlayStyle.dark,
          ),
          inputDecorationTheme: InputDecorationTheme(
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
            ),
            filled: true,
            fillColor: Colors.grey[100],
          ),
        ),
        // منع الوصول غير المصرح به
        navigatorObservers: [SecureNavigatorObserver()],
        // تعيين المسارات
        initialRoute: '/login',
        onGenerateRoute: _generateRoute,
        // منع التنقل الخلفي
        onUnknownRoute: (settings) => MaterialPageRoute(
          builder: (_) => const LoginPage(),
        ),
        // تأمين التطبيق
        builder: (context, child) {
          return GestureDetector(
            onTap: () {
              // إخفاء لوحة المفاتيح عند النقر خارج حقل الإدخال
              FocusScope.of(context).unfocus();
            },
            child: BlocListener<AuthBloc, AuthState>(
              listener: (context, state) {
                if (state is AuthUnauthenticated) {
                  // إعادة التوجيه إلى صفحة تسجيل الدخول
                  Navigator.of(context).pushNamedAndRemoveUntil(
                    '/login',
                        (route) => false,
                  );
                }
              },
              child: child ?? const SizedBox.shrink(),
            ),
          );
        },
      ),
    );
  }

  Route<dynamic>? _generateRoute(RouteSettings settings) {
    // التحقق من المسارات والوصول
    switch (settings.name) {
      case '/login':
        return MaterialPageRoute(
          builder: (_) => const LoginPage(),
          settings: settings,
        );
      case '/signup':
        return MaterialPageRoute(
          builder: (_) => const SignupPage(),
          settings: settings,
        );
      case '/home':
        return MaterialPageRoute(
          builder: (_) => BlocBuilder<AuthBloc, AuthState>(
            builder: (context, state) {
              if (state is AuthAuthenticated) {
                return const HomePage();
              }
              return const LoginPage();
            },
          ),
          settings: settings,
        );
      case '/search':
        return MaterialPageRoute(
          builder: (_) => BlocBuilder<AuthBloc, AuthState>(
            builder: (context, state) {
              if (state is AuthAuthenticated) {
                return const SearchPage();
              }
              return const LoginPage();
            },
          ),
          settings: settings,
        );
      default:
        return null;
    }
  }
}

// مراقب التنقل الآمن
class SecureNavigatorObserver extends NavigatorObserver {
  final SecureLogger _logger = di.sl<SecureLogger>();

  @override
  void didPush(Route<dynamic> route, Route<dynamic>? previousRoute) {
    super.didPush(route, previousRoute);
    _logger.log(
      'Navigation: Pushed ${route.settings.name}',
      level: LogLevel.info,
      category: SecurityCategory.session,
    );
  }

  @override
  void didPop(Route<dynamic> route, Route<dynamic>? previousRoute) {
    super.didPop(route, previousRoute);
    _logger.log(
      'Navigation: Popped ${route.settings.name}',
      level: LogLevel.info,
      category: SecurityCategory.session,
    );
  }

  @override
  void didRemove(Route<dynamic> route, Route<dynamic>? previousRoute) {
    super.didRemove(route, previousRoute);
    _logger.log(
      'Navigation: Removed ${route.settings.name}',
      level: LogLevel.info,
      category: SecurityCategory.session,
    );
  }

  @override
  void didReplace({Route<dynamic>? newRoute, Route<dynamic>? oldRoute}) {
    super.didReplace(newRoute: newRoute, oldRoute: oldRoute);
    _logger.log(
      'Navigation: Replaced ${oldRoute?.settings.name} with ${newRoute?.settings.name}',
      level: LogLevel.info,
      category: SecurityCategory.session,
    );
  }
}