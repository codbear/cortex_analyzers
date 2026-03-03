#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test pour les analyseurs VirusTotal
Usage: python test_virustotal_analyzers.py
"""

import json
import subprocess
import sys
import os
from pathlib import Path

class VirusTotalTester:
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.results = []
        
    def test_hash_analyzer(self, test_hash, hash_type, api_key):
        """Test l'analyseur de hash avec un hash connu"""
        print(f"\n🔍 Test Hash Analyzer ({hash_type}): {test_hash}")
        
        # Configuration temporaire
        config = {
            "data": test_hash,
            "dataType": "hash",
            "config": {
                "api_key": api_key,
                "api_timeout": 30,
                "enable_ssl_verify": True
            }
        }
        
        try:
            # Changer dans le répertoire hash_enrich
            os.chdir(self.base_path / "hash_enrich")
            
            # Exécuter l'analyseur
            process = subprocess.Popen(
                ["python3", "hash_enrich.py"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input=json.dumps(config))
            
            if process.returncode == 0:
                try:
                    result = json.loads(stdout)
                    print("✅ Succès!")
                    
                    # Dans Cortex, les données sont dans 'full' quand success=True
                    if result.get('success') == True and 'full' in result:
                        data = result['full']
                        print(f"   - Hash trouvé: {data.get('found', 'N/A')}")
                        if data.get('found'):
                            rep = data.get('reputation', 'Unknown')
                            stats = data.get('detection_stats', {})
                            ratio = stats.get('detection_ratio', 'N/A') if isinstance(stats, dict) else 'N/A'
                            print(f"   - Réputation: {rep}")
                            print(f"   - Détections: {ratio}")
                    else:
                        print(f"   - Résultat: {result.get('success', 'Unknown')}")
                    return True
                except json.JSONDecodeError:
                    print(f"❌ Erreur de parsing JSON: {stdout}")
                    return False
            else:
                print(f"❌ Erreur d'exécution: {stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Exception: {str(e)}")
            return False
        finally:
            os.chdir(self.base_path)

    def test_ip_analyzer(self, test_ip, api_key):
        """Test l'analyseur IP avec une IP connue"""
        print(f"\n🌐 Test IP Analyzer: {test_ip}")
        
        # Configuration temporaire  
        config = {
            "data": test_ip,
            "dataType": "ip",
            "config": {
                "api_key": api_key,
                "api_timeout": 30,
                "enable_ssl_verify": True,
                "skip_private_ips": False  # Pour tester même les IPs privées
            }
        }
        
        try:
            # Changer dans le répertoire ip_enrich
            os.chdir(self.base_path / "ip_enrich")
            
            # Exécuter l'analyseur
            process = subprocess.Popen(
                ["python3", "ip_enrich.py"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input=json.dumps(config))
            
            if process.returncode == 0:
                try:
                    result = json.loads(stdout)
                    print("✅ Succès!")
                    
                    # Dans Cortex, les données sont dans 'full' quand success=True
                    if result.get('success') == True and 'full' in result:
                        data = result['full']
                        print(f"   - IP valide: {data.get('valid', 'N/A')}")
                        print(f"   - IP publique: {data.get('public', 'N/A')}")
                        if data.get('country'):
                            print(f"   - Pays: {data.get('country')}")
                        if data.get('reputation'):
                            print(f"   - Réputation: {data.get('reputation')}")
                            stats = data.get('detection_stats', {})
                            ratio = stats.get('detection_ratio', 'N/A') if isinstance(stats, dict) else 'N/A'
                            print(f"   - Détections: {ratio}")
                    else:
                        print(f"   - Résultat: {result.get('success', 'Unknown')}")
                    return True
                except json.JSONDecodeError:
                    print(f"❌ Erreur de parsing JSON: {stdout}")
                    return False
            else:
                print(f"❌ Erreur d'exécution: {stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Exception: {str(e)}")
            return False
        finally:
            os.chdir(self.base_path)

    def run_tests(self):
        """Exécute tous les tests"""
        print("🧪 Test des Analyseurs VirusTotal")
        print("=" * 50)
        
        # Demander la clé API
        api_key = input("🔑 Entrez votre clé API VirusTotal: ").strip()
        if not api_key:
            print("❌ Clé API requise pour les tests")
            return False
        
        print(f"\nUtilisation de la clé API: {api_key[:8]}{'*' * (len(api_key) - 8)}")
        
        success_count = 0
        total_tests = 0
        
        # Tests Hash Analyzer
        test_hashes = [
            ("d41d8cd98f00b204e9800998ecf8427e", "md5"),    # Fichier vide (connu)
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),  # Fichier vide (connu)
            ("44d88612fea8a8f36de82e1278abb02f", "md5"),    # Hash de test malveillant fictif
        ]
        
        for test_hash, hash_type in test_hashes:
            total_tests += 1
            if self.test_hash_analyzer(test_hash, hash_type, api_key):
                success_count += 1
        
        # Tests IP Analyzer
        test_ips = [
            "8.8.8.8",      # Google DNS (propre)
            "1.1.1.1",      # Cloudflare DNS (propre)
            "127.0.0.1",    # Localhost (pour tester la validation)
        ]
        
        for test_ip in test_ips:
            total_tests += 1
            if self.test_ip_analyzer(test_ip, api_key):
                success_count += 1
        
        # Résultats finaux
        print("\n" + "=" * 50)
        print(f"📊 Résultats: {success_count}/{total_tests} tests réussis")
        
        if success_count == total_tests:
            print("🎉 Tous les tests sont passés! Les analyseurs sont prêts.")
        elif success_count > 0:
            print("⚠️  Certains tests ont échoué. Vérifiez la configuration.")  
        else:
            print("💥 Tous les tests ont échoué. Vérifiez votre clé API et la connectivité.")
        
        return success_count == total_tests

if __name__ == "__main__":
    tester = VirusTotalTester()
    success = tester.run_tests()
    sys.exit(0 if success else 1)