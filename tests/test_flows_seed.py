# Must import test base before the Controller
from base import BaseTest, FlowTest, FlowStep

from seedsigner.models.settings import SettingsConstants
from seedsigner.models.seed import Seed
from seedsigner.views.view import MainMenuView
from seedsigner.views import seed_views, scan_views



class TestSeedFlows(FlowTest):

    def test_scan_seedqr_flow(self):
        """
            Selecting "Scan" from the MainMenuView and scanning a SeedQR should enter the
            Finalize Seed flow and end at the SeedOptionsView.
        """
        def load_seed_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("0000" * 11 + "0003")

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_seed_into_decoder),  # simulate read SeedQR; ret val is ignored
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView),
        ])


    def test_mnemonic_entry_flow(self):
        """
            Manually entering a mnemonic should land at the Finalize Seed flow and end at
            the SeedOptionsView.
        """
        def test_with_mnemonic(mnemonic):
            sequence = [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, is_redirect=True),  # When no seeds are loaded it auto-redirects to LoadSeedView
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.TYPE_12WORD if len(mnemonic) == 12 else seed_views.LoadSeedView.TYPE_24WORD),
            ]

            # Now add each manual word entry step
            for word in mnemonic:
                sequence.append(
                    FlowStep(seed_views.SeedMnemonicEntryView, screen_return_value=word)
                )
            
            # With the mnemonic completely entered, we land on the SeedFinalizeView
            sequence += [
                FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
                FlowStep(seed_views.SeedOptionsView),
            ]

            self.run_sequence(sequence)

        # Test data from iancoleman.io; 12- and 24-word mnemonic
        test_with_mnemonic("tone flat shed cool census soul paddle boy flight fantasy stem social".split())

        BaseTest.reset_controller()

        test_with_mnemonic("cotton artefact spy mind wing there echo steak child oak awful host despair online bicycle divorce middle firm diamond rare execute chimney almost hollow".split())


    def test_invalid_mnemonic(self):
        """ Should be able to go back and edit or discard an invalid mnemonic """
        # Test data from iancoleman.io
        mnemonic = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()
        sequence = [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, is_redirect=True),  # When no seeds are loaded it auto-redirects to LoadSeedView
            FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.TYPE_12WORD if len(mnemonic) == 12 else seed_views.LoadSeedView.TYPE_24WORD),
        ]
        for word in mnemonic[:-1]:
            sequence.append(FlowStep(seed_views.SeedMnemonicEntryView, screen_return_value=word))

        sequence += [
            FlowStep(seed_views.SeedMnemonicEntryView, screen_return_value="zoo"),  # But finish with an INVALID checksum word
            FlowStep(seed_views.SeedMnemonicInvalidView, button_data_selection=seed_views.SeedMnemonicInvalidView.EDIT),
        ]

        # Restarts from first word
        for word in mnemonic[:-1]:
            sequence.append(FlowStep(seed_views.SeedMnemonicEntryView, screen_return_value=word))

        sequence += [
            FlowStep(seed_views.SeedMnemonicEntryView, screen_return_value="zebra"),  # provide yet another invalid checksum word
            FlowStep(seed_views.SeedMnemonicInvalidView, button_data_selection=seed_views.SeedMnemonicInvalidView.DISCARD),
            FlowStep(MainMenuView),
        ]

        self.run_sequence(sequence)


    def test_export_xpub_flow(self):
        """
            Selecting "Export XPUB" from the SeedOptionsView should enter the Export XPUB flow and end at the MainMenuView
        """
        # Load a finalized Seed into the Controller
        mnemonic = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()
        self.controller.storage.set_pending_seed(Seed(mnemonic=mnemonic))
        self.controller.storage.finalize_pending_seed()

        SIG_TYPE = self.settings.get_multiselect_value_display_names(SettingsConstants.SETTING__SIG_TYPES)[0] # 0: single-sig
        SCRIPT_TYPE = self.settings.get_multiselect_value_display_names(SettingsConstants.SETTING__SCRIPT_TYPES)[0] # 0: native segwit
        COORDINATOR = self.settings.get_multiselect_value_display_names(SettingsConstants.SETTING__COORDINATORS)[0] # 0: bluwallet
        COORDINATOR = self.settings.get_multiselect_value_display_names(SettingsConstants.SETTING__COORDINATORS)[3] # 0: specter

        # TEST PASSES BUT RAISES WARNING
        # File "seedsigner-dev/src/seedsigner/gui/components.py", line 316, in __post_init__
        #   if not self.auto_line_break or full_text_width < self.supersampled_width - (2 * self.edge_padding * self.supersampling_factor):
        # TypeError: '<' not supported between instances of 'int' and 'MagicMock'
        # warnings.warn(pytest.PytestUnhandledThreadExceptionWarning(msg))
        self.run_sequence(
            initial_destination_view_args=dict(seed_num=0),
            sequence=[
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.EXPORT_XPUB),
                FlowStep(seed_views.SeedExportXpubSigTypeView, button_data_selection=SIG_TYPE),
                FlowStep(seed_views.SeedExportXpubScriptTypeView, button_data_selection=SCRIPT_TYPE),
                FlowStep(seed_views.SeedExportXpubCoordinatorView, button_data_selection=COORDINATOR),
                FlowStep(seed_views.SeedExportXpubWarningView, screen_return_value=0),
                FlowStep(seed_views.SeedExportXpubDetailsView, screen_return_value=0),
                FlowStep(seed_views.SeedExportXpubQRDisplayView, screen_return_value=0),
                FlowStep(MainMenuView),
            ]
        )


    def test_export_xpub_skip_sig_type_flow(self):
        """
            Export XPUB flows w/o user choices when no other options for sig_types, script_types, and/or coordinators
        """
        # Load a finalized Seed into the Controller
        mnemonic = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()
        self.controller.storage.set_pending_seed(Seed(mnemonic=mnemonic))
        self.controller.storage.finalize_pending_seed()

        # exclusively set only one choice for each of sig_types, script_types and coordinators
        self.settings.update(dict(sig_types=['ms'], script_types=['nes'], coordinators=['spa']), False)

        # TEST PASSES BUT RAISES WARNING
        # File "seedsigner-dev/src/seedsigner/gui/components.py", line 316, in __post_init__
        #   if not self.auto_line_break or full_text_width < self.supersampled_width - (2 * self.edge_padding * self.supersampling_factor):
        # TypeError: '<' not supported between instances of 'int' and 'MagicMock'
        # warnings.warn(pytest.PytestUnhandledThreadExceptionWarning(msg))
        self.run_sequence(
            initial_destination_view_args=dict(seed_num=0),
            sequence=[
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.EXPORT_XPUB),
                FlowStep(seed_views.SeedExportXpubSigTypeView, is_redirect=True),
                FlowStep(seed_views.SeedExportXpubScriptTypeView, is_redirect=True),
                FlowStep(seed_views.SeedExportXpubCoordinatorView, is_redirect=True),
                FlowStep(seed_views.SeedExportXpubWarningView, screen_return_value=0),
                FlowStep(seed_views.SeedExportXpubDetailsView, screen_return_value=0),
                FlowStep(seed_views.SeedExportXpubQRDisplayView, screen_return_value=0),
                FlowStep(MainMenuView),
            ]
        )


    def test_discard_seed_flow(self):
        """
            Selecting "Discard Seed" from the SeedOptionsView should enter the Discard Seed flow and 
            remove the in-memory seed from the Controller.
        """
        # Load a finalized Seed into the Controller
        mnemonic = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()
        self.controller.storage.set_pending_seed(Seed(mnemonic=mnemonic))
        self.controller.storage.finalize_pending_seed()

        self.run_sequence(
            initial_destination_view_args=dict(seed_num=0),
            sequence=[
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.DISCARD),
                FlowStep(seed_views.SeedDiscardView, button_data_selection=seed_views.SeedDiscardView.DISCARD),
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
                FlowStep(seed_views.SeedsMenuView, is_redirect=True),  # When no seeds are loaded it auto-redirects to LoadSeedView
                FlowStep(seed_views.LoadSeedView),
            ]
        )
