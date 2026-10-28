from parser import mac_lookup

def test_vendor_names_with_commas_are_kept_whole(tmp_path):
    oui = tmp_path / 'oui.csv'
    oui.write_text('286FB9,Nokia Shanghai Bell Co., Ltd.\n00-50-04,3COM\n')
    try:
        assert mac_lookup.load_oui_database(str(oui)) == 2
        assert mac_lookup.lookup_manufacturer('28:6f:b9:00:00:01') == 'Nokia Shanghai Bell Co., Ltd.'
        assert mac_lookup.lookup_manufacturer('00:50:04:93:70:67') == '3COM'
        assert mac_lookup.lookup_manufacturer('aa:bb:cc:00:00:00') == mac_lookup.UNKNOWN_VENDOR
    finally:
        mac_lookup.load_oui_database()  # back to the bundled database for other tests

def test_bundled_database():
    assert mac_lookup.lookup_manufacturer('28:6f:b9:00:00:01') == 'Nokia Shanghai Bell Co., Ltd.'
