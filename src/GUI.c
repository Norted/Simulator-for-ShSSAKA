#include <gtk/gtk.h>
#include <SSAKA.h>

struct Buttons {
  GtkWidget *button_keys;
  GtkWidget *button_params;
  GtkWidget *button_setup;
  GtkWidget *button_akaSeverSignVer;
};

static void activate (GtkApplication *app, gpointer *user_data);
/*  BUTTON FUNCTIONS  */
static void akaSetup (GtkWidget *button, GtkWidget *spinButton);
static void akaServerSignVerify (GtkWidget *button, GtkWidget *label);
static void openKeysDialogue (GtkWidget *button, gpointer *user_data);
static void openParamDialogue (GtkWidget *button, gpointer *user_data);
/*  OTHER FUNCTIONS */
static void updateSpinButton (GtkWidget *spinButton, GtkWidget *label);
void updateLabel( GtkLabel *label, gchar *string);
void setButtons (gboolean enabled);
void setCSS ();

/*  GLOBALS */
guint64 lg_Y = 100;
gchar *lg_consoleName = "\n - - - - - - SSAKA Console - - - - - -\n";
struct Buttons buttons;

/*  MAIN  */
int main (int argc, char **argv) {
  GtkApplication *app;
  int status;

  gtk_init (&argc,&argv);
  setCSS ();
  app = gtk_application_new ("vut.ssaka.demo", GTK_WINDOW_TOPLEVEL);
  g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
  status = g_application_run (G_APPLICATION (app), argc, argv);
  g_object_unref (app);

  return status;
}

/*  APP GUI FUNCTION  */
static void activate (GtkApplication *app, gpointer *user_data) {
  GtkWidget *window = gtk_application_window_new (app);
  GtkWidget *grid = gtk_grid_new ();
  GtkWidget *box_message = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 2);
  GtkWidget *box_aka = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
  GtkWidget *box_info = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 2);
  GtkWidget *box_console = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);

  GtkWidget *label_message = gtk_label_new ("Message:");
  GtkWidget *spinButton_message = gtk_spin_button_new_with_range (1, 10000, 1);
  GtkWidget *label_console = gtk_label_new (lg_consoleName);

  buttons.button_keys = gtk_button_new_with_label ("Keys");
  buttons.button_params = gtk_button_new_with_label ("Parameters");
  buttons.button_setup = gtk_button_new_with_label ("Setup");
  buttons.button_akaSeverSignVer = gtk_button_new_with_label ("AKA Server Sign Verify");

  setButtons(FALSE);
  
  /*  WINDOW Setup  */
  gtk_window_set_title (GTK_WINDOW (window), "SSAKA Demonstartor");
  gtk_widget_set_name (window, "window");
  gtk_window_set_icon_from_file (window, "./icon.jpg", NULL);
  gtk_container_set_border_width (GTK_CONTAINER (window), 10);
  gtk_window_set_resizable(window, FALSE);
  gtk_widget_set_name (grid, "grid");
  gtk_container_add (GTK_CONTAINER (window), grid);

  gtk_box_set_homogeneous(GTK_BOX (box_message), TRUE);
  gtk_grid_attach (GTK_GRID (grid), box_message, 0, 0, 2, 1);
  gtk_box_set_homogeneous(GTK_BOX (box_aka), TRUE);
  gtk_grid_attach (GTK_GRID (grid), box_aka, 0, 1, 2, 1);
  gtk_box_set_homogeneous(GTK_BOX (box_console), TRUE);
  gtk_grid_attach (GTK_GRID (grid), box_console, 0, 2, 2, 1);

  gtk_box_pack_start (GTK_BOX (box_aka), box_info, TRUE, TRUE, 2);

  /*  MESSAGE Label and Entry Box */
  gtk_box_pack_start (GTK_BOX (box_message), label_message, TRUE, TRUE, 2);
  gtk_widget_set_name (GTK_LABEL (label_message), "label");
  gtk_box_pack_end (GTK_BOX (box_message), spinButton_message, TRUE, TRUE, 2);
  gtk_spin_button_set_value (GTK_SPIN_BUTTON (spinButton_message), (double) 100);
  g_signal_connect (GTK_SPIN_BUTTON (spinButton_message), "value-changed", G_CALLBACK (updateSpinButton), label_console);
  gtk_widget_set_name (GTK_SPIN_BUTTON (spinButton_message), "spinButton");
  
  /*  BUTTONS
   *  |------ INFO BUTTONS
   *        |--> KEYS Button
   *        |--> PARAMETERS Button
   *  |--> SETUP Button
   *  |--> AKA SERVER SIGN VERIFY Button
   */
  g_signal_connect (G_OBJECT (buttons.button_keys), "clicked", G_CALLBACK (openKeysDialogue), NULL);
  gtk_widget_set_name (GTK_BUTTON (buttons.button_keys), "button");
  gtk_widget_set_sensitive (GTK_BUTTON (buttons.button_keys), FALSE);
  gtk_box_pack_start (GTK_BOX (box_info), buttons.button_keys, TRUE, TRUE, 2);

  g_signal_connect (G_OBJECT (buttons.button_params), "clicked", G_CALLBACK (openParamDialogue), NULL);
  gtk_widget_set_name (GTK_BUTTON (buttons.button_params), "button");
  gtk_widget_set_sensitive (GTK_BUTTON (buttons.button_params), FALSE);
  gtk_box_pack_end (GTK_BOX (box_info), buttons.button_params, TRUE, TRUE, 2);

  g_signal_connect (G_OBJECT (buttons.button_setup), "clicked", G_CALLBACK (akaSetup), GTK_LABEL (label_console));
  gtk_widget_set_name (GTK_BUTTON (buttons.button_setup), "button");
  gtk_box_pack_start (GTK_BOX (box_aka), buttons.button_setup, TRUE, TRUE, 2);

  g_signal_connect (G_OBJECT (buttons.button_akaSeverSignVer), "clicked", G_CALLBACK (akaServerSignVerify), GTK_LABEL (label_console));
  gtk_widget_set_name (GTK_BUTTON (buttons.button_akaSeverSignVer), "button");
  gtk_widget_set_sensitive (GTK_BUTTON (buttons.button_akaSeverSignVer), FALSE);
  gtk_box_pack_end (GTK_BOX (box_aka), buttons.button_akaSeverSignVer, TRUE, TRUE, 2);
  
  /*  CONSOLE   */
  gtk_label_set_selectable (GTK_LABEL (label_console), TRUE);
  gtk_label_set_line_wrap_mode (GTK_LABEL (label_console), PANGO_WRAP_CHAR);
  gtk_widget_set_name (GTK_LABEL (label_console), "console");
  gtk_box_pack_start (GTK_BOX (box_console), label_console, TRUE, TRUE, 2);
  
  gtk_widget_show_all (window);
}

/*  BUTTON FUNCTIONS  */
static void akaSetup (GtkWidget *button, GtkWidget *label) {
  setup();
  setButtons(TRUE);

  gchar *dmp = g_strconcat (lg_consoleName, g_strdup_printf ("\n\x20\x20>\tParameters initialized!\n"));
  updateLabel (GTK_LABEL (label), dmp);
}

static void akaServerSignVerify (GtkWidget *button, GtkWidget *label) {
  struct ServerSign server = aka_serverSignVerify(lg_Y, g_aka_serverKeys.sk, g_aka_clientKeys.pk);
  if (server.tau_s == 0) {
    // g_strconcat (gtk_label_get_text (console), g_strdup_printf (str));
    gchar *dmp = g_strconcat (lg_consoleName, g_strdup_printf ("\n\x20\x20>\tTAU_S = %d\n\tVerification failed! :(\n\tProtocol ends.\n", server.tau_s));
    updateLabel (GTK_LABEL (label), dmp);
  }
  else {
    gchar *dmp = g_strconcat (lg_consoleName, g_strdup_printf ("\n\x20\x20>\tTAU_S = %d\n\tVerification proceeded! :)\n\tProtocol continues.\n", server.tau_s));
    updateLabel (GTK_LABEL (label), dmp);
  }
}

static void openKeysDialogue (GtkWidget *button, gpointer *user_data) {
  GtkWidget *dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_NONE, "Generated keys");

  gchar *message = g_strdup_printf (" --- Server --- \nID:\t%u\nPK:\t%u\nSK:\t%u\n\n --- Client --- \nID:\t%u\nPK:\t%u\nSK:\t%u\n\n==================\n\n",
    g_aka_serverKeys.ID, g_aka_serverKeys.pk, g_aka_serverKeys.sk, g_aka_clientKeys.ID, g_aka_clientKeys.pk, g_aka_clientKeys.sk);
  for (int i = 0; i < G_NUMOFDEVICES; i++) {
    message = g_strconcat (message, g_strdup_printf ("--- Device %d ---\nID:\t%u\nPK:\t%u\nSK:\t%u\n\n",
      i+1, g_aka_devicesKeys[i].ID, g_aka_devicesKeys[i].pk, g_aka_devicesKeys[i].sk));
  }
  message = g_strconcat (message, g_strdup_printf ("\nEscape by pressing ESC ..."));

  gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog), g_locale_to_utf8 (message, -1, NULL, NULL, NULL));
  gtk_widget_set_name (GTK_DIALOG (dialog), "dialog");
  gtk_dialog_run (GTK_DIALOG (dialog));

  gtk_widget_destroy (dialog);
  g_free (message);
}

static void openParamDialogue (GtkWidget *button, gpointer *user_data) {
  GtkWidget *dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_NONE, "Parameters");

  gchar *message = g_strdup_printf ("Z*_%u:\n[", g_q);
  for (int i = 0; i <= g_generatorsLen; i++) {
    message = g_strconcat (message, g_strdup_printf (" %d ", g_generators[i]));
  }
  message = g_strconcat (message, g_strdup_printf ("]\n\n==================\n\nY:\t%lu\n\nQ:\t%u\n\nG:\t%u\n\n\nEscape by pressing ESC ...", lg_Y, g_q, g_g));

  gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog), g_locale_to_utf8 (message, -1, NULL, NULL, NULL));
  gtk_widget_set_name (GTK_DIALOG (dialog), "dialog");
  gtk_dialog_run (GTK_DIALOG (dialog));

  gtk_widget_destroy (dialog);
  g_free (message);
}

/*  OTHER FUNCTIONS */
static void updateSpinButton (GtkWidget *spinButton, GtkWidget *label) {
  lg_Y = (guint64) gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (spinButton));
  gchar *dmp = g_strconcat (lg_consoleName, g_strdup_printf ("\n\x20\x20>\tMessage value changed to %lu!\n", lg_Y));
  updateLabel (GTK_LABEL (label), dmp);
}

void updateLabel( GtkLabel *label, gchar *string) {
  gtk_label_set_text (GTK_LABEL (label), g_locale_to_utf8 (string, -1, NULL, NULL, NULL));
  g_free (string);
}

void setButtons (gboolean enabled) {
  gtk_widget_set_sensitive (GTK_BUTTON (buttons.button_akaSeverSignVer), enabled);
  gtk_widget_set_sensitive (GTK_BUTTON (buttons.button_keys), enabled);
  gtk_widget_set_sensitive (GTK_BUTTON (buttons.button_params), enabled);
}

void setCSS () {
  GtkCssProvider *provider;
  GdkDisplay *display;
  GdkScreen *screen;

  provider = gtk_css_provider_new ();
  display = gdk_display_get_default ();
  screen = gdk_display_get_default_screen (display);
  gtk_style_context_add_provider_for_screen (screen, GTK_STYLE_PROVIDER (provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

  const gchar *cssFile = "style.css";
  GError *error = 0;

  gtk_css_provider_load_from_file(provider, g_file_new_for_path(cssFile), &error);
  g_object_unref (provider);
}
