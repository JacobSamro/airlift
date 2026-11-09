// Fixture app for the on-device OTA e2e. Every piece of state the Maestro
// flows assert on is a single "key:value" Text with a testID, so the flows
// can match exact values.
import { useState } from 'react';
import { Image, Pressable, StyleSheet, Text, View } from 'react-native';
import * as Updates from 'expo-updates';

import { EXTRA, MARKER } from './marker';

export default function App() {
  const [status, setStatus] = useState('idle');
  // An image only some published updates carry (never embedded): proves a
  // brand-new asset was downloaded and is loadable.
  const [extra, setExtra] = useState(EXTRA ? 'pending' : 'none');

  async function checkAndApply() {
    setStatus('checking');
    try {
      const check = await Updates.checkForUpdateAsync();
      if (!check.isAvailable && !check.isRollBackToEmbedded) {
        setStatus(`up-to-date:${check.reason ?? 'none'}`);
        return;
      }
      setStatus('fetching');
      const fetched = await Updates.fetchUpdateAsync();
      if (!fetched.isNew && !fetched.isRollBackToEmbedded) {
        setStatus('fetch-not-new');
        return;
      }
      setStatus('reloading');
      await Updates.reloadAsync();
    } catch (e) {
      setStatus(`error:${e?.code ?? ''}:${e?.message ?? String(e)}`);
    }
  }

  return (
    <View style={styles.container}>
      <Image source={require('./assets/logo.png')} style={styles.logo} testID="logo" />
      <Text testID="marker">{`marker:${MARKER}`}</Text>
      <Text testID="origin">{`origin:${Updates.isEmbeddedLaunch ? 'embedded' : 'update'}`}</Text>
      <Text testID="update-id">{`update-id:${Updates.updateId ?? 'none'}`}</Text>
      <Text testID="channel">{`channel:${Updates.channel ?? 'none'}`}</Text>
      <Text testID="status">{`status:${status}`}</Text>
      {EXTRA ? (
        <Image
          source={EXTRA}
          style={styles.logo}
          onLoad={() => setExtra('loaded')}
          onError={() => setExtra('error')}
        />
      ) : null}
      <Text testID="extra">{`extra:${extra}`}</Text>
      <Pressable testID="check" onPress={checkAndApply} style={styles.button}>
        <Text style={styles.buttonText}>Check for update</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 8, padding: 24 },
  logo: { width: 48, height: 48 },
  button: { marginTop: 16, paddingHorizontal: 20, paddingVertical: 12, backgroundColor: '#222', borderRadius: 8 },
  buttonText: { color: '#fff' },
});
