import 'package:flutter_test/flutter_test.dart';
import 'package:smart_utility_app/main.dart';

void main() {
  testWidgets('login screen loads', (WidgetTester tester) async {
    await tester.pumpWidget(const ZeroTrustResearchApp());
    expect(find.text('AI-Driven Zero Trust Security'), findsOneWidget);
  });
}
