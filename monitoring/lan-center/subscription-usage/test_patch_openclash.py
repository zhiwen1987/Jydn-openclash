import unittest
import patch_openclash as patch


class PatchTests(unittest.TestCase):
    def test_unknown_or_duplicate_upstream_anchor_is_refused(self):
        for fn in (patch.controller,patch.widget,lambda t:patch.status(t,'fixture'),lambda t:patch.upload(t,'fixture')):
            with self.assertRaises(ValueError):fn('unrecognized upstream')
        with self.assertRaises(ValueError):patch.controller('function sub_info_get()\nfunction sub_info_get()\n')

    def test_controller_owns_only_metadata_endpoint(self):
        original='unchanged before\nfunction sub_info_get()\nUNCHANGED_BODY\nend\nunchanged after'
        result=patch.controller(original)
        self.assertIn("require, 'luci.jydn_subscription_usage'",result)
        self.assertTrue(result.endswith('UNCHANGED_BODY\nend\nunchanged after'))
        with self.assertRaises(ValueError):patch.controller(result)

    def test_native_cache_accepts_zero_sources_and_decreasing_counts(self):
        original=';'.join(['r.providers.length>0?this.currentConfigFile===e&&this.displaySubscriptionInfo(r)',
            's=1800;','g!==p&&p>g&&(u=!0)','c&&c.status==200&&d.providers.length>0',
            'SubscriptionManager.startAutoUpdate()},6e4*15)','"sub_info_"'])
        result=patch.status(original,'SAFE_UI')
        self.assertIn('(r.providers.length>0||r.auto_mode)',result)
        self.assertIn('p>g&&!d.auto_mode',result)
        self.assertIn('d.providers.length>0||d.auto_mode',result)
        self.assertIn('s=r.auto_mode?15:1800;',result)
        self.assertTrue(result.endswith('SAFE_UI'))


if __name__=='__main__':unittest.main()
