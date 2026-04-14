import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  runApp(const ZeroTrustResearchApp());
}

String formatTimestamp(String value) {
  final date = DateTime.tryParse(value);
  if (date == null) return value;

  String two(int n) => n.toString().padLeft(2, '0');

  return '${two(date.day)}/${two(date.month)}/${date.year} '
      '${two(date.hour)}:${two(date.minute)}';
}

class IncidentRecord {
  final String username;
  final String role;
  final String requestedResource;
  final String location;
  final String decision;
  final String action;
  final String reason;
  final int trustScore;
  final int riskScore;
  final String timestamp;
  final bool trustedDevice;
  final bool mfaEnabled;
  final bool unusualTime;
  final bool suspiciousTraffic;
  final int failedAttempts;

  const IncidentRecord({
    required this.username,
    required this.role,
    required this.requestedResource,
    required this.location,
    required this.decision,
    required this.action,
    required this.reason,
    required this.trustScore,
    required this.riskScore,
    required this.timestamp,
    required this.trustedDevice,
    required this.mfaEnabled,
    required this.unusualTime,
    required this.suspiciousTraffic,
    required this.failedAttempts,
  });

  Map<String, dynamic> toMap() {
    return {
      'username': username,
      'role': role,
      'requestedResource': requestedResource,
      'location': location,
      'decision': decision,
      'action': action,
      'reason': reason,
      'trustScore': trustScore,
      'riskScore': riskScore,
      'timestamp': timestamp,
      'trustedDevice': trustedDevice,
      'mfaEnabled': mfaEnabled,
      'unusualTime': unusualTime,
      'suspiciousTraffic': suspiciousTraffic,
      'failedAttempts': failedAttempts,
    };
  }

  factory IncidentRecord.fromMap(Map<String, dynamic> map) {
    return IncidentRecord(
      username: map['username']?.toString() ?? '',
      role: map['role']?.toString() ?? '',
      requestedResource: map['requestedResource']?.toString() ?? '',
      location: map['location']?.toString() ?? '',
      decision: map['decision']?.toString() ?? '',
      action: map['action']?.toString() ?? '',
      reason: map['reason']?.toString() ?? '',
      trustScore: (map['trustScore'] as num?)?.toInt() ?? 0,
      riskScore: (map['riskScore'] as num?)?.toInt() ?? 0,
      timestamp: map['timestamp']?.toString() ?? '',
      trustedDevice: map['trustedDevice'] as bool? ?? false,
      mfaEnabled: map['mfaEnabled'] as bool? ?? false,
      unusualTime: map['unusualTime'] as bool? ?? false,
      suspiciousTraffic: map['suspiciousTraffic'] as bool? ?? false,
      failedAttempts: (map['failedAttempts'] as num?)?.toInt() ?? 0,
    );
  }
}

class SecurityResult {
  final int trustScore;
  final int riskScore;
  final String decision;
  final String action;
  final List<String> reasons;

  const SecurityResult({
    required this.trustScore,
    required this.riskScore,
    required this.decision,
    required this.action,
    required this.reasons,
  });
}

class DashboardStats {
  final int totalRequests;
  final int allowCount;
  final int verifyCount;
  final int blockCount;
  final int suspiciousSessions;
  final int unknownLocationSessions;
  final int highRiskSessions;
  final int sensitiveResourceRequests;
  final double averageTrust;
  final double averageRisk;
  final Map<String, int> resourceCounts;

  const DashboardStats({
    required this.totalRequests,
    required this.allowCount,
    required this.verifyCount,
    required this.blockCount,
    required this.suspiciousSessions,
    required this.unknownLocationSessions,
    required this.highRiskSessions,
    required this.sensitiveResourceRequests,
    required this.averageTrust,
    required this.averageRisk,
    required this.resourceCounts,
  });

  factory DashboardStats.empty() {
    return const DashboardStats(
      totalRequests: 0,
      allowCount: 0,
      verifyCount: 0,
      blockCount: 0,
      suspiciousSessions: 0,
      unknownLocationSessions: 0,
      highRiskSessions: 0,
      sensitiveResourceRequests: 0,
      averageTrust: 0,
      averageRisk: 0,
      resourceCounts: {},
    );
  }

  factory DashboardStats.fromRecords(List<IncidentRecord> records) {
    if (records.isEmpty) return DashboardStats.empty();

    int allowCount = 0;
    int verifyCount = 0;
    int blockCount = 0;
    int suspiciousSessions = 0;
    int unknownLocationSessions = 0;
    int highRiskSessions = 0;
    int sensitiveResourceRequests = 0;
    int totalTrust = 0;
    int totalRisk = 0;
    final resourceCounts = <String, int>{};

    for (final record in records) {
      if (record.decision == 'ALLOW') allowCount++;
      if (record.decision == 'VERIFY') verifyCount++;
      if (record.decision == 'BLOCK') blockCount++;
      if (record.suspiciousTraffic) suspiciousSessions++;
      if (record.location == 'Unknown') unknownLocationSessions++;
      if (record.riskScore >= 60) highRiskSessions++;
      if (record.requestedResource == 'Admin Panel' ||
          record.requestedResource == 'Firewall Console') {
        sensitiveResourceRequests++;
      }

      totalTrust += record.trustScore;
      totalRisk += record.riskScore;
      resourceCounts.update(
        record.requestedResource,
        (value) => value + 1,
        ifAbsent: () => 1,
      );
    }

    return DashboardStats(
      totalRequests: records.length,
      allowCount: allowCount,
      verifyCount: verifyCount,
      blockCount: blockCount,
      suspiciousSessions: suspiciousSessions,
      unknownLocationSessions: unknownLocationSessions,
      highRiskSessions: highRiskSessions,
      sensitiveResourceRequests: sensitiveResourceRequests,
      averageTrust: totalTrust / records.length,
      averageRisk: totalRisk / records.length,
      resourceCounts: resourceCounts,
    );
  }

  String get topResource {
    if (resourceCounts.isEmpty) return 'None yet';
    final entries = resourceCounts.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    return entries.first.key;
  }
}

class SecurityEngine {
  static SecurityResult evaluate({
    required String role,
    required String requestedResource,
    required String location,
    required bool trustedDevice,
    required bool mfaEnabled,
    required bool unusualTime,
    required bool suspiciousTraffic,
    required int failedAttempts,
  }) {
    int trustScore = 50;
    int riskScore = 0;
    final reasons = <String>[];

    if (requestedResource == 'Public Dashboard') {
      trustScore += 5;
      reasons.add('Low sensitivity resource requested');
    } else if (requestedResource == 'Internal File Server') {
      riskScore += 10;
      reasons.add('Moderate sensitivity resource requested');
    } else if (requestedResource == 'SIEM Dashboard') {
      riskScore += 15;
      reasons.add('Security monitoring resource requested');
    } else if (requestedResource == 'Firewall Console') {
      trustScore -= 10;
      riskScore += 25;
      reasons.add('High sensitivity firewall access requested');
    } else if (requestedResource == 'Admin Panel') {
      trustScore -= 15;
      riskScore += 30;
      reasons.add('Critical admin resource requested');
    }

    if (trustedDevice) {
      trustScore += 20;
      reasons.add('Trusted device detected');
    } else {
      trustScore -= 15;
      riskScore += 20;
      reasons.add('Unknown or unmanaged device');
    }

    if (location == 'Office') {
      trustScore += 15;
      reasons.add('Login from approved office network');
    } else if (location == 'Home') {
      trustScore += 5;
      reasons.add('Login from known remote location');
    } else {
      trustScore -= 15;
      riskScore += 20;
      reasons.add('Login from unknown location');
    }

    if (mfaEnabled) {
      trustScore += 15;
      reasons.add('MFA enabled');
    } else {
      trustScore -= 10;
      riskScore += 15;
      reasons.add('MFA disabled');
    }

    if (role == 'Admin') {
      riskScore += 15;
      reasons.add('High privilege admin access');
    } else if (role == 'Analyst') {
      riskScore += 8;
      reasons.add('Moderate privilege analyst access');
    } else {
      reasons.add('Standard user access');
    }

    if (failedAttempts > 0 && failedAttempts < 3) {
      trustScore -= 5;
      riskScore += 10;
      reasons.add('Some failed login attempts detected');
    }

    if (failedAttempts >= 3) {
      trustScore -= 20;
      riskScore += 25;
      reasons.add('Multiple failed login attempts');
    }

    if (unusualTime) {
      trustScore -= 10;
      riskScore += 15;
      reasons.add('Access requested at unusual time');
    }

    if (suspiciousTraffic) {
      trustScore -= 25;
      riskScore += 30;
      reasons.add('Anomaly engine flagged suspicious traffic');
    }

    if (trustedDevice &&
        mfaEnabled &&
        location == 'Office' &&
        !suspiciousTraffic &&
        failedAttempts == 0) {
      trustScore += 5;
      reasons.add('Strong baseline zero trust posture');
    }

    trustScore = trustScore.clamp(0, 100);
    riskScore = riskScore.clamp(0, 100);

    String decision;
    String action;

    if (trustScore >= 75 && riskScore <= 30) {
      decision = 'ALLOW';
      action = 'Grant access and continue monitoring the session';
    } else if (trustScore >= 45 && riskScore <= 70) {
      decision = 'VERIFY';
      action = 'Require step-up authentication and device verification';
    } else {
      decision = 'BLOCK';
      action = 'Block access, isolate the session, and raise a security alert';
    }

    return SecurityResult(
      trustScore: trustScore,
      riskScore: riskScore,
      decision: decision,
      action: action,
      reasons: reasons,
    );
  }
}

class IncidentStorage {
  static const String storageKey = 'incident_history';

  static Future<List<IncidentRecord>> load() async {
    final prefs = await SharedPreferences.getInstance();
    final rawList = prefs.getStringList(storageKey) ?? [];
    final records = rawList
        .map((item) => IncidentRecord.fromMap(jsonDecode(item)))
        .toList();
    return records.reversed.toList();
  }

  static Future<void> saveRecord(IncidentRecord record) async {
    final prefs = await SharedPreferences.getInstance();
    final current = prefs.getStringList(storageKey) ?? [];
    current.add(jsonEncode(record.toMap()));
    await prefs.setStringList(storageKey, current);
  }

  static Future<void> replaceAll(List<IncidentRecord> records) async {
    final prefs = await SharedPreferences.getInstance();
    final raw = records.map((record) => jsonEncode(record.toMap())).toList();
    await prefs.setStringList(storageKey, raw);
  }

  static Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(storageKey);
  }

  static Future<void> loadSampleDataset() async {
    final now = DateTime.now();

    IncidentRecord makeRecord({
      required String username,
      required String role,
      required String requestedResource,
      required String location,
      required bool trustedDevice,
      required bool mfaEnabled,
      required bool unusualTime,
      required bool suspiciousTraffic,
      required int failedAttempts,
      required DateTime timestamp,
    }) {
      final result = SecurityEngine.evaluate(
        role: role,
        requestedResource: requestedResource,
        location: location,
        trustedDevice: trustedDevice,
        mfaEnabled: mfaEnabled,
        unusualTime: unusualTime,
        suspiciousTraffic: suspiciousTraffic,
        failedAttempts: failedAttempts,
      );

      return IncidentRecord(
        username: username,
        role: role,
        requestedResource: requestedResource,
        location: location,
        decision: result.decision,
        action: result.action,
        reason: result.reasons.join(', '),
        trustScore: result.trustScore,
        riskScore: result.riskScore,
        timestamp: timestamp.toIso8601String(),
        trustedDevice: trustedDevice,
        mfaEnabled: mfaEnabled,
        unusualTime: unusualTime,
        suspiciousTraffic: suspiciousTraffic,
        failedAttempts: failedAttempts,
      );
    }

    final sampleRecords = <IncidentRecord>[
      makeRecord(
        username: 'analyst01',
        role: 'Analyst',
        requestedResource: 'SIEM Dashboard',
        location: 'Office',
        trustedDevice: true,
        mfaEnabled: true,
        unusualTime: false,
        suspiciousTraffic: false,
        failedAttempts: 0,
        timestamp: now.subtract(const Duration(minutes: 10)),
      ),
      makeRecord(
        username: 'admin01',
        role: 'Admin',
        requestedResource: 'Firewall Console',
        location: 'Unknown',
        trustedDevice: false,
        mfaEnabled: false,
        unusualTime: true,
        suspiciousTraffic: true,
        failedAttempts: 4,
        timestamp: now.subtract(const Duration(minutes: 24)),
      ),
      makeRecord(
        username: 'user01',
        role: 'User',
        requestedResource: 'Internal File Server',
        location: 'Home',
        trustedDevice: true,
        mfaEnabled: true,
        unusualTime: false,
        suspiciousTraffic: false,
        failedAttempts: 1,
        timestamp: now.subtract(const Duration(minutes: 37)),
      ),
      makeRecord(
        username: 'admin02',
        role: 'Admin',
        requestedResource: 'Admin Panel',
        location: 'Office',
        trustedDevice: true,
        mfaEnabled: true,
        unusualTime: true,
        suspiciousTraffic: false,
        failedAttempts: 0,
        timestamp: now.subtract(const Duration(minutes: 49)),
      ),
      makeRecord(
        username: 'user02',
        role: 'User',
        requestedResource: 'Public Dashboard',
        location: 'Home',
        trustedDevice: true,
        mfaEnabled: true,
        unusualTime: false,
        suspiciousTraffic: false,
        failedAttempts: 0,
        timestamp: now.subtract(const Duration(minutes: 62)),
      ),
      makeRecord(
        username: 'user03',
        role: 'User',
        requestedResource: 'Firewall Console',
        location: 'Unknown',
        trustedDevice: false,
        mfaEnabled: false,
        unusualTime: true,
        suspiciousTraffic: true,
        failedAttempts: 5,
        timestamp: now.subtract(const Duration(minutes: 83)),
      ),
    ];

    await replaceAll(sampleRecords);
  }
}

class ZeroTrustResearchApp extends StatelessWidget {
  const ZeroTrustResearchApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Zero Trust Security Automation',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        primarySwatch: Colors.indigo,
        scaffoldBackgroundColor: const Color(0xfff4f7fb),
        cardTheme: CardThemeData(
          elevation: 4,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(10),
          ),
        ),
      ),
      home: const LoginPage(),
    );
  }
}

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final formKey = GlobalKey<FormState>();
  final userController = TextEditingController();
  final passController = TextEditingController();

  void login() {
    if (!formKey.currentState!.validate()) return;

    if (passController.text.trim() == '1234') {
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(
          builder: (_) => HomePage(username: userController.text.trim()),
        ),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Invalid password. Use 1234 for demo.')),
      );
    }
  }

  @override
  void dispose() {
    userController.dispose();
    passController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        width: double.infinity,
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [Color(0xff0f172a), Color(0xff1d4ed8)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
        ),
        child: Center(
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: SizedBox(
                width: 340,
                child: Form(
                  key: formKey,
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const CircleAvatar(
                        radius: 34,
                        backgroundColor: Colors.indigo,
                        child:
                            Icon(Icons.security, color: Colors.white, size: 34),
                      ),
                      const SizedBox(height: 16),
                      const Text(
                        'AI-Driven Zero Trust Security',
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          fontSize: 22,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'Mobile Computing Project Prototype',
                        style: TextStyle(color: Colors.grey),
                      ),
                      const SizedBox(height: 20),
                      TextFormField(
                        controller: userController,
                        decoration: const InputDecoration(
                          labelText: 'Username',
                          prefixIcon: Icon(Icons.person),
                        ),
                        validator: (value) {
                          if (value == null || value.trim().isEmpty) {
                            return 'Enter username';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 14),
                      TextFormField(
                        controller: passController,
                        obscureText: true,
                        decoration: const InputDecoration(
                          labelText: 'Password',
                          prefixIcon: Icon(Icons.lock),
                        ),
                        validator: (value) {
                          if (value == null || value.trim().isEmpty) {
                            return 'Enter password';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 18),
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton(
                          onPressed: login,
                          child: const Text('Login'),
                        ),
                      ),
                      const SizedBox(height: 10),
                      const Text(
                        'Demo: use any username and password 1234',
                        style: TextStyle(fontSize: 12, color: Colors.grey),
                        textAlign: TextAlign.center,
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class HomePage extends StatefulWidget {
  final String username;

  const HomePage({super.key, required this.username});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  int currentIndex = 0;
  int refreshToken = 0;

  String get screenTitle {
    switch (currentIndex) {
      case 0:
        return 'Dashboard';
      case 1:
        return 'Trust Evaluation';
      case 2:
        return 'Incident History';
      default:
        return 'About Project';
    }
  }

  void markDataChanged() {
    setState(() {
      refreshToken++;
    });
  }

  Future<void> loadSampleDataset() async {
    await IncidentStorage.loadSampleDataset();
    if (!mounted) return;
    markDataChanged();
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Sample dataset loaded')),
    );
  }

  Future<void> clearAllIncidents() async {
    await IncidentStorage.clear();
    if (!mounted) return;
    markDataChanged();
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('All incidents cleared')),
    );
  }

  void changeTab(int index) {
    setState(() {
      currentIndex = index;
    });
  }

  @override
  Widget build(BuildContext context) {
    final pages = [
      DashboardPage(
        key: ValueKey('dashboard-$refreshToken'),
        username: widget.username,
        onLoadSampleData: loadSampleDataset,
        onClearData: clearAllIncidents,
        onOpenEvaluation: () => changeTab(1),
      ),
      TrustEvaluationPage(
        username: widget.username,
        onEvaluationSaved: markDataChanged,
      ),
      IncidentHistoryPage(
        key: ValueKey('history-$refreshToken'),
        onHistoryChanged: markDataChanged,
      ),
      const AboutProjectPage(),
    ];

    return Scaffold(
      appBar: AppBar(
        title: Text(screenTitle),
      ),
      drawer: Drawer(
        child: ListView(
          children: [
            DrawerHeader(
              decoration: const BoxDecoration(
                gradient: LinearGradient(colors: [Colors.indigo, Colors.blue]),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const CircleAvatar(
                    radius: 28,
                    backgroundColor: Colors.white,
                    child: Icon(Icons.verified_user, color: Colors.indigo),
                  ),
                  const SizedBox(height: 10),
                  const Text(
                    'Security Automation Lab',
                    style: TextStyle(color: Colors.white, fontSize: 20),
                  ),
                  Text(
                    'Logged in as ${widget.username}',
                    style: const TextStyle(color: Colors.white70),
                  ),
                ],
              ),
            ),
            ListTile(
              leading: const Icon(Icons.dashboard),
              title: const Text('Dashboard'),
              onTap: () {
                Navigator.pop(context);
                changeTab(0);
              },
            ),
            ListTile(
              leading: const Icon(Icons.security),
              title: const Text('Trust Evaluation'),
              onTap: () {
                Navigator.pop(context);
                changeTab(1);
              },
            ),
            ListTile(
              leading: const Icon(Icons.history),
              title: const Text('Incident History'),
              onTap: () {
                Navigator.pop(context);
                changeTab(2);
              },
            ),
            ListTile(
              leading: const Icon(Icons.info),
              title: const Text('About Project'),
              onTap: () {
                Navigator.pop(context);
                changeTab(3);
              },
            ),
            ListTile(
              leading: const Icon(Icons.logout),
              title: const Text('Logout'),
              onTap: () {
                Navigator.pushReplacement(
                  context,
                  MaterialPageRoute(builder: (_) => const LoginPage()),
                );
              },
            ),
          ],
        ),
      ),
      body: pages[currentIndex],
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: currentIndex,
        onTap: changeTab,
        type: BottomNavigationBarType.fixed,
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.dashboard),
            label: 'Dashboard',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.security),
            label: 'Evaluate',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.history),
            label: 'History',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.info),
            label: 'About',
          ),
        ],
      ),
    );
  }
}

class DashboardPage extends StatelessWidget {
  final String username;
  final Future<void> Function() onLoadSampleData;
  final Future<void> Function() onClearData;
  final VoidCallback onOpenEvaluation;

  const DashboardPage({
    super.key,
    required this.username,
    required this.onLoadSampleData,
    required this.onClearData,
    required this.onOpenEvaluation,
  });

  Future<void> confirmLoadSampleData(BuildContext context) async {
    final shouldLoad = await showDialog<bool>(
          context: context,
          builder: (_) => AlertDialog(
            title: const Text('Load Sample Dataset'),
            content: const Text(
              'This will replace current incident data with sample research data. Continue?',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('No'),
              ),
              ElevatedButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('Yes'),
              ),
            ],
          ),
        ) ??
        false;

    if (shouldLoad) {
      await onLoadSampleData();
    }
  }

  Future<void> confirmClearData(BuildContext context) async {
    final shouldClear = await showDialog<bool>(
          context: context,
          builder: (_) => AlertDialog(
            title: const Text('Clear Incident Data'),
            content: const Text('Do you want to remove all stored incidents?'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('No'),
              ),
              ElevatedButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('Yes'),
              ),
            ],
          ),
        ) ??
        false;

    if (shouldClear) {
      await onClearData();
    }
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<IncidentRecord>>(
      future: IncidentStorage.load(),
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return const Center(child: CircularProgressIndicator());
        }

        final records = snapshot.data ?? [];
        final stats = DashboardStats.fromRecords(records);

        if (records.isEmpty) {
          return RefreshIndicator(
            onRefresh: () async {},
            child: ListView(
              physics: const AlwaysScrollableScrollPhysics(),
              padding: const EdgeInsets.all(14),
              children: [
                Container(
                  padding: const EdgeInsets.all(18),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(14),
                    gradient: const LinearGradient(
                      colors: [Color(0xff111827), Color(0xff2563eb)],
                    ),
                  ),
                  child: Text(
                    'Welcome, $username\nRun an access request or load a sample dataset to generate live security metrics.',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      height: 1.4,
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(18),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'No incident data yet',
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            fontSize: 18,
                          ),
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          'This dashboard becomes fully working after you evaluate access requests or load a sample research dataset.',
                        ),
                        const SizedBox(height: 16),
                        SizedBox(
                          width: double.infinity,
                          child: ElevatedButton.icon(
                            onPressed: onOpenEvaluation,
                            icon: const Icon(Icons.play_arrow),
                            label: const Text('Run First Evaluation'),
                          ),
                        ),
                        const SizedBox(height: 10),
                        SizedBox(
                          width: double.infinity,
                          child: OutlinedButton.icon(
                            onPressed: () => confirmLoadSampleData(context),
                            icon: const Icon(Icons.dataset),
                            label: const Text('Load Sample Dataset'),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          );
        }

        final resourceEntries = stats.resourceCounts.entries.toList()
          ..sort((a, b) => b.value.compareTo(a.value));

        return RefreshIndicator(
          onRefresh: () async {},
          child: ListView(
            physics: const AlwaysScrollableScrollPhysics(),
            padding: const EdgeInsets.all(14),
            children: [
              Container(
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(14),
                  gradient: const LinearGradient(
                    colors: [Color(0xff111827), Color(0xff2563eb)],
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'AI-Driven Network Security Automation',
                      style: Theme.of(context).textTheme.titleLarge?.copyWith(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                          ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      'Active user: $username',
                      style: const TextStyle(color: Colors.white70),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      'Top requested resource: ${stats.topResource}',
                      style: const TextStyle(color: Colors.white70),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              GridView.count(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                crossAxisCount: 2,
                mainAxisSpacing: 12,
                crossAxisSpacing: 12,
                childAspectRatio: 1.15,
                children: [
                  MetricCard(
                    title: 'Total Requests',
                    value: stats.totalRequests.toString(),
                    icon: Icons.analytics,
                    color: Colors.indigo,
                  ),
                  MetricCard(
                    title: 'Allowed',
                    value: stats.allowCount.toString(),
                    icon: Icons.check_circle,
                    color: Colors.green,
                  ),
                  MetricCard(
                    title: 'Verify',
                    value: stats.verifyCount.toString(),
                    icon: Icons.verified_user,
                    color: Colors.orange,
                  ),
                  MetricCard(
                    title: 'Blocked',
                    value: stats.blockCount.toString(),
                    icon: Icons.block,
                    color: Colors.red,
                  ),
                ],
              ),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Security Posture',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(height: 12),
                      Text(
                          'Average Trust Score: ${stats.averageTrust.toStringAsFixed(1)}'),
                      const SizedBox(height: 6),
                      LinearProgressIndicator(value: stats.averageTrust / 100),
                      const SizedBox(height: 14),
                      Text(
                          'Average Risk Score: ${stats.averageRisk.toStringAsFixed(1)}'),
                      const SizedBox(height: 6),
                      LinearProgressIndicator(
                        value: stats.averageRisk / 100,
                        color: Colors.red,
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              GridView.count(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                crossAxisCount: 2,
                mainAxisSpacing: 12,
                crossAxisSpacing: 12,
                childAspectRatio: 1.25,
                children: [
                  MiniMetricCard(
                    title: 'High Risk Sessions',
                    value: stats.highRiskSessions.toString(),
                    color: Colors.red,
                  ),
                  MiniMetricCard(
                    title: 'Suspicious Traffic',
                    value: stats.suspiciousSessions.toString(),
                    color: Colors.deepOrange,
                  ),
                  MiniMetricCard(
                    title: 'Unknown Locations',
                    value: stats.unknownLocationSessions.toString(),
                    color: Colors.purple,
                  ),
                  MiniMetricCard(
                    title: 'Sensitive Resource Requests',
                    value: stats.sensitiveResourceRequests.toString(),
                    color: Colors.blue,
                  ),
                ],
              ),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Resource Activity',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(height: 10),
                      ...resourceEntries.map(
                        (entry) => ListTile(
                          dense: true,
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.storage),
                          title: Text(entry.key),
                          trailing: Text('${entry.value}'),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Recent Decisions',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(height: 10),
                      ...records.take(4).map(
                            (record) => ListTile(
                              contentPadding: EdgeInsets.zero,
                              leading: DecisionChip(decision: record.decision),
                              title: Text(record.requestedResource),
                              subtitle: Text(
                                '${record.username} • ${formatTimestamp(record.timestamp)}',
                              ),
                              trailing: Text('Risk ${record.riskScore}'),
                            ),
                          ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: onOpenEvaluation,
                      icon: const Icon(Icons.play_arrow),
                      label: const Text('New Evaluation'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () => confirmLoadSampleData(context),
                      icon: const Icon(Icons.dataset),
                      label: const Text('Sample Data'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: () => confirmClearData(context),
                  icon: const Icon(Icons.delete),
                  label: const Text('Clear Stored Data'),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class TrustEvaluationPage extends StatefulWidget {
  final String username;
  final VoidCallback onEvaluationSaved;

  const TrustEvaluationPage({
    super.key,
    required this.username,
    required this.onEvaluationSaved,
  });

  @override
  State<TrustEvaluationPage> createState() => _TrustEvaluationPageState();
}

class _TrustEvaluationPageState extends State<TrustEvaluationPage> {
  final formKey = GlobalKey<FormState>();
  final failedAttemptsController = TextEditingController(text: '0');

  String selectedRole = 'User';
  String selectedResource = 'SIEM Dashboard';
  String selectedLocation = 'Office';
  bool trustedDevice = true;
  bool mfaEnabled = true;
  bool unusualTime = false;
  bool suspiciousTraffic = false;
  bool isSaving = false;
  SecurityResult? result;

  void resetForm() {
    setState(() {
      selectedRole = 'User';
      selectedResource = 'SIEM Dashboard';
      selectedLocation = 'Office';
      trustedDevice = true;
      mfaEnabled = true;
      unusualTime = false;
      suspiciousTraffic = false;
      failedAttemptsController.text = '0';
      result = null;
    });
  }

  Future<void> evaluateAccess() async {
    if (!formKey.currentState!.validate()) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please correct the form values')),
      );
      return;
    }

    setState(() {
      isSaving = true;
    });

    final failedAttempts =
        int.tryParse(failedAttemptsController.text.trim()) ?? 0;

    final output = SecurityEngine.evaluate(
      role: selectedRole,
      requestedResource: selectedResource,
      location: selectedLocation,
      trustedDevice: trustedDevice,
      mfaEnabled: mfaEnabled,
      unusualTime: unusualTime,
      suspiciousTraffic: suspiciousTraffic,
      failedAttempts: failedAttempts,
    );

    final record = IncidentRecord(
      username: widget.username,
      role: selectedRole,
      requestedResource: selectedResource,
      location: selectedLocation,
      decision: output.decision,
      action: output.action,
      reason: output.reasons.join(', '),
      trustScore: output.trustScore,
      riskScore: output.riskScore,
      timestamp: DateTime.now().toIso8601String(),
      trustedDevice: trustedDevice,
      mfaEnabled: mfaEnabled,
      unusualTime: unusualTime,
      suspiciousTraffic: suspiciousTraffic,
      failedAttempts: failedAttempts,
    );

    await IncidentStorage.saveRecord(record);

    if (!mounted) return;

    setState(() {
      result = output;
      isSaving = false;
    });

    widget.onEvaluationSaved();

    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Incident saved to local audit history')),
    );

    await showDialog<void>(
      context: context,
      builder: (_) => AlertDialog(
        title: Text('Decision: ${output.decision}'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Trust Score: ${output.trustScore}'),
            Text('Risk Score: ${output.riskScore}'),
            const SizedBox(height: 10),
            Text(output.action),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  Widget buildSwitchTile({
    required String title,
    required String subtitle,
    required bool value,
    required ValueChanged<bool> onChanged,
  }) {
    return Card(
      child: SwitchListTile(
        value: value,
        onChanged: onChanged,
        title: Text(title),
        subtitle: Text(subtitle),
      ),
    );
  }

  Widget buildResultCard(SecurityResult data) {
    Color statusColor;
    if (data.decision == 'ALLOW') {
      statusColor = Colors.green;
    } else if (data.decision == 'VERIFY') {
      statusColor = Colors.orange;
    } else {
      statusColor = Colors.red;
    }

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: statusColor.withOpacity(0.08),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: statusColor.withOpacity(0.35)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Decision: ${data.decision}',
            style: TextStyle(
              color: statusColor,
              fontWeight: FontWeight.bold,
              fontSize: 18,
            ),
          ),
          const SizedBox(height: 8),
          Text('Trust Score: ${data.trustScore}/100'),
          Text('Risk Score: ${data.riskScore}/100'),
          const SizedBox(height: 8),
          Text('Action: ${data.action}'),
          const SizedBox(height: 10),
          const Text(
            'Reasoning:',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 6),
          ...data.reasons.map((reason) => Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Text('- $reason'),
              )),
        ],
      ),
    );
  }

  @override
  void dispose() {
    failedAttemptsController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(14),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'What this screen does',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
                const SizedBox(height: 8),
                Text(
                  'This simulates a real zero trust access request for user ${widget.username}. '
                  'The app checks identity context, device trust, authentication strength, '
                  'location, anomalies, and requested resource sensitivity before making a decision.',
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Form(
              key: formKey,
              child: Column(
                children: [
                  TextFormField(
                    initialValue: widget.username,
                    readOnly: true,
                    decoration: const InputDecoration(
                      labelText: 'Requester',
                      prefixIcon: Icon(Icons.person),
                    ),
                  ),
                  const SizedBox(height: 12),
                  DropdownButtonFormField<String>(
                    value: selectedRole,
                    decoration: const InputDecoration(
                      labelText: 'User Role',
                      prefixIcon: Icon(Icons.badge),
                    ),
                    items: const [
                      DropdownMenuItem(value: 'User', child: Text('User')),
                      DropdownMenuItem(
                          value: 'Analyst', child: Text('Analyst')),
                      DropdownMenuItem(value: 'Admin', child: Text('Admin')),
                    ],
                    onChanged: (value) {
                      setState(() => selectedRole = value!);
                    },
                  ),
                  const SizedBox(height: 12),
                  DropdownButtonFormField<String>(
                    value: selectedResource,
                    decoration: const InputDecoration(
                      labelText: 'Requested Resource',
                      prefixIcon: Icon(Icons.storage),
                    ),
                    items: const [
                      DropdownMenuItem(
                        value: 'Public Dashboard',
                        child: Text('Public Dashboard'),
                      ),
                      DropdownMenuItem(
                        value: 'Internal File Server',
                        child: Text('Internal File Server'),
                      ),
                      DropdownMenuItem(
                        value: 'SIEM Dashboard',
                        child: Text('SIEM Dashboard'),
                      ),
                      DropdownMenuItem(
                        value: 'Firewall Console',
                        child: Text('Firewall Console'),
                      ),
                      DropdownMenuItem(
                        value: 'Admin Panel',
                        child: Text('Admin Panel'),
                      ),
                    ],
                    onChanged: (value) {
                      setState(() => selectedResource = value!);
                    },
                  ),
                  const SizedBox(height: 12),
                  DropdownButtonFormField<String>(
                    value: selectedLocation,
                    decoration: const InputDecoration(
                      labelText: 'Login Location',
                      prefixIcon: Icon(Icons.location_on),
                    ),
                    items: const [
                      DropdownMenuItem(value: 'Office', child: Text('Office')),
                      DropdownMenuItem(value: 'Home', child: Text('Home')),
                      DropdownMenuItem(
                          value: 'Unknown', child: Text('Unknown')),
                    ],
                    onChanged: (value) {
                      setState(() => selectedLocation = value!);
                    },
                  ),
                  const SizedBox(height: 12),
                  TextFormField(
                    controller: failedAttemptsController,
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(
                      labelText: 'Failed Login Attempts',
                      prefixIcon: Icon(Icons.error_outline),
                    ),
                    validator: (value) {
                      if (value == null || value.trim().isEmpty) {
                        return 'Enter failed attempts';
                      }
                      final parsed = int.tryParse(value.trim());
                      if (parsed == null || parsed < 0 || parsed > 10) {
                        return 'Enter a number from 0 to 10';
                      }
                      return null;
                    },
                  ),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        buildSwitchTile(
          title: 'Trusted Device',
          subtitle: 'Device is registered and policy-compliant',
          value: trustedDevice,
          onChanged: (value) => setState(() => trustedDevice = value),
        ),
        buildSwitchTile(
          title: 'MFA Enabled',
          subtitle: 'User completed multi-factor authentication',
          value: mfaEnabled,
          onChanged: (value) => setState(() => mfaEnabled = value),
        ),
        buildSwitchTile(
          title: 'Unusual Login Time',
          subtitle: 'Request happened outside normal access hours',
          value: unusualTime,
          onChanged: (value) => setState(() => unusualTime = value),
        ),
        buildSwitchTile(
          title: 'Suspicious Traffic',
          subtitle: 'Anomaly engine detected risky session behavior',
          value: suspiciousTraffic,
          onChanged: (value) => setState(() => suspiciousTraffic = value),
        ),
        const SizedBox(height: 14),
        Row(
          children: [
            Expanded(
              child: ElevatedButton.icon(
                onPressed: isSaving ? null : evaluateAccess,
                icon: const Icon(Icons.play_arrow),
                label: Text(isSaving ? 'Processing...' : 'Run Evaluation'),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: OutlinedButton.icon(
                onPressed: resetForm,
                icon: const Icon(Icons.refresh),
                label: const Text('Reset'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        if (result != null) buildResultCard(result!),
      ],
    );
  }
}

class IncidentHistoryPage extends StatefulWidget {
  final VoidCallback onHistoryChanged;

  const IncidentHistoryPage({super.key, required this.onHistoryChanged});

  @override
  State<IncidentHistoryPage> createState() => _IncidentHistoryPageState();
}

class _IncidentHistoryPageState extends State<IncidentHistoryPage> {
  late Future<List<IncidentRecord>> futureRecords;
  String selectedFilter = 'ALL';

  @override
  void initState() {
    super.initState();
    futureRecords = IncidentStorage.load();
  }

  Future<void> refreshRecords() async {
    setState(() {
      futureRecords = IncidentStorage.load();
    });
  }

  Future<void> clearHistory() async {
    final shouldClear = await showDialog<bool>(
          context: context,
          builder: (_) => AlertDialog(
            title: const Text('Clear History'),
            content: const Text('Do you want to clear all incident history?'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('No'),
              ),
              ElevatedButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('Yes'),
              ),
            ],
          ),
        ) ??
        false;

    if (!shouldClear) return;

    await IncidentStorage.clear();
    widget.onHistoryChanged();
    await refreshRecords();

    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Incident history cleared')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<IncidentRecord>>(
      future: futureRecords,
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return const Center(child: CircularProgressIndicator());
        }

        final allRecords = snapshot.data ?? [];
        final records = selectedFilter == 'ALL'
            ? allRecords
            : allRecords
                .where((item) => item.decision == selectedFilter)
                .toList();

        return RefreshIndicator(
          onRefresh: refreshRecords,
          child: ListView(
            physics: const AlwaysScrollableScrollPhysics(),
            padding: const EdgeInsets.all(14),
            children: [
              Wrap(
                spacing: 8,
                children: ['ALL', 'ALLOW', 'VERIFY', 'BLOCK']
                    .map(
                      (filter) => ChoiceChip(
                        label: Text(filter),
                        selected: selectedFilter == filter,
                        onSelected: (_) {
                          setState(() {
                            selectedFilter = filter;
                          });
                        },
                      ),
                    )
                    .toList(),
              ),
              const SizedBox(height: 12),
              if (allRecords.isEmpty)
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(18),
                    child: Column(
                      children: [
                        const Icon(Icons.history, size: 48, color: Colors.grey),
                        const SizedBox(height: 12),
                        const Text(
                          'No incident history yet',
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            fontSize: 18,
                          ),
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          'Run evaluations first to build the audit trail for your project.',
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 14),
                        OutlinedButton.icon(
                          onPressed: refreshRecords,
                          icon: const Icon(Icons.refresh),
                          label: const Text('Refresh'),
                        ),
                      ],
                    ),
                  ),
                )
              else ...[
                Card(
                  child: ListTile(
                    leading: const Icon(Icons.analytics),
                    title: Text('Filtered records: ${records.length}'),
                    subtitle:
                        Text('Total stored records: ${allRecords.length}'),
                    trailing: IconButton(
                      onPressed: clearHistory,
                      icon: const Icon(Icons.delete),
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                ...records.map(
                  (item) => Card(
                    child: ExpansionTile(
                      leading: DecisionChip(decision: item.decision),
                      title: Text(item.requestedResource),
                      subtitle: Text(
                        '${item.username} • ${formatTimestamp(item.timestamp)}',
                      ),
                      childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                      children: [
                        Align(
                          alignment: Alignment.centerLeft,
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('Role: ${item.role}'),
                              Text('Location: ${item.location}'),
                              Text('Trust Score: ${item.trustScore}'),
                              Text('Risk Score: ${item.riskScore}'),
                              Text('Failed Attempts: ${item.failedAttempts}'),
                              Text('Action: ${item.action}'),
                              const SizedBox(height: 8),
                              const Text(
                                'Reasoning:',
                                style: TextStyle(fontWeight: FontWeight.bold),
                              ),
                              const SizedBox(height: 4),
                              Text(item.reason),
                              const SizedBox(height: 8),
                              Text(
                                'Trusted Device: ${item.trustedDevice ? "Yes" : "No"}',
                              ),
                              Text(
                                'MFA Enabled: ${item.mfaEnabled ? "Yes" : "No"}',
                              ),
                              Text(
                                'Unusual Time: ${item.unusualTime ? "Yes" : "No"}',
                              ),
                              Text(
                                'Suspicious Traffic: ${item.suspiciousTraffic ? "Yes" : "No"}',
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ],
          ),
        );
      },
    );
  }
}

class AboutProjectPage extends StatelessWidget {
  const AboutProjectPage({super.key});

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(14),
      children: const [
        InfoSectionCard(
          title: 'How this app matches the research topic',
          points: [
            'The app simulates zero trust access control for protected network resources.',
            'Every access request is checked before access is granted.',
            'Inputs such as role, location, device trust, MFA, failed attempts, unusual time, and suspicious traffic are used to calculate trust and risk.',
            'The system then automates the decision: ALLOW, VERIFY, or BLOCK.',
          ],
        ),
        SizedBox(height: 12),
        InfoSectionCard(
          title: 'What makes it AI-assisted',
          points: [
            'This project uses rule-based anomaly detection, not a fully trained production AI model.',
            'Suspicious traffic and unusual behavior act as anomaly indicators.',
            'It is a prototype for AI-assisted security automation.',
          ],
        ),
        SizedBox(height: 12),
        InfoSectionCard(
          title: 'Mobile Computing concepts implemented',
          points: [
            'Login screen and navigation',
            'Drawer and bottom navigation bar',
            'Forms with validation',
            'Dropdowns, switches, buttons, cards',
            'ListView and GridView',
            'Dialogs and SnackBars',
            'Local data storage using SharedPreferences',
            'Dynamic dashboard and audit history',
          ],
        ),
        SizedBox(height: 12),
        InfoSectionCard(
          title: ' ',
          points: [
            '',
          ],
        ),
      ],
    );
  }
}

class MetricCard extends StatelessWidget {
  final String title;
  final String value;
  final IconData icon;
  final Color color;

  const MetricCard({
    super.key,
    required this.title,
    required this.value,
    required this.icon,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        gradient: LinearGradient(
          colors: [color.withOpacity(0.85), color],
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, color: Colors.white, size: 34),
            const SizedBox(height: 10),
            Text(
              value,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 24,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              title,
              textAlign: TextAlign.center,
              style: const TextStyle(color: Colors.white),
            ),
          ],
        ),
      ),
    );
  }
}

class MiniMetricCard extends StatelessWidget {
  final String title;
  final String value;
  final Color color;

  const MiniMetricCard({
    super.key,
    required this.title,
    required this.value,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withOpacity(0.22)),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              value,
              style: TextStyle(
                color: color,
                fontSize: 22,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              title,
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}

class DecisionChip extends StatelessWidget {
  final String decision;

  const DecisionChip({super.key, required this.decision});

  @override
  Widget build(BuildContext context) {
    Color color;
    if (decision == 'ALLOW') {
      color = Colors.green;
    } else if (decision == 'VERIFY') {
      color = Colors.orange;
    } else {
      color = Colors.red;
    }

    return Chip(
      label: Text(
        decision,
        style: const TextStyle(color: Colors.white),
      ),
      backgroundColor: color,
    );
  }
}

class InfoSectionCard extends StatelessWidget {
  final String title;
  final List<String> points;

  const InfoSectionCard({
    super.key,
    required this.title,
    required this.points,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 17,
              ),
            ),
            const SizedBox(height: 10),
            ...points.map(
              (point) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text('- $point'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
