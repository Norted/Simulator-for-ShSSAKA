//#include <AKA.h>
#include <ShSSAKA.h>
#include <support_functions.h>
#include <gtk/gtk.h>
#include <globals.h>

struct Buttons
{
  GtkWidget *button_keys;
  GtkWidget *button_params;
  GtkWidget *button_setup;
  GtkWidget *button_akaSeverSignVer;
  GtkWidget *button_addShare;
  GtkWidget *button_revShare;
};

static void activate(GtkApplication *app, gpointer *user_data);
/*  BUTTON FUNCTIONS  */
static void akaSetup(GtkWidget *button, GtkWidget *spinButton);
static void akaServerSignVerify(GtkWidget *button, GtkWidget *label);
static void ssakaClientProofVer(GtkWidget *button, GtkWidget *label);
static void ssakaAddShare(GtkWidget *button, GtkWidget *label);
static void ssakaRevShare(GtkWidget *button, GtkWidget *label);
static void openKeysDialogue(GtkWidget *button, gpointer *user_data);
static void openParamDialogue(GtkWidget *button, gpointer *user_data);
/*  OTHER FUNCTIONS */
static void updateSpinButton_message(GtkWidget *spinButton, GtkWidget *label);
static void updateSpinButton_add(GtkWidget *spinButton, GtkWidget *label);
void updateEntry_add(GtkWidget *entry, GtkWidget *label);
void updateEntry_revoke(GtkWidget *entry, GtkWidget *label);
void updateLabel(GtkLabel *label, gchar *string);
void checkNoise(GtkWidget *entry, GtkWidget *label);
void checkMessage(GtkWidget *entry, GtkWidget *label);
void setButtons(gboolean enabled);
void setCSS();

/*  GLOBALS */
// Keychains
struct aka_Keychain g_serverKeys;
struct aka_Keychain g_aka_clientKeys;
struct ssaka_Keychain g_ssaka_devicesKeys[G_NUMOFDEVICES];

struct paillier_Keychain g_paiKeys;
EC_POINT *pk_c;

// Other globals
struct globals g_globals;
unsigned int currentNumberOfDevices = 4;
BIGNUM *g_range;
unsigned int paillier_inited = 0;
unsigned int pre_noise = 0;
unsigned int pre_message = 0;

// File names
const char *restrict file_precomputed_noise = "../precomputed_values/precomputation_noise.json";
const char *restrict file_precomputed_message = "../precomputed_values/precomputation_message.json";
cJSON *json_noise;
cJSON *json_message;

BIGNUM *Y;
unsigned int setup_toggled = 0;

guint64 add_number = 1;

guint used_devs[10];
guint size_used = 0;
guint revoke_devs[7];
guint size_revoke = 0;

gchar *lg_consoleName = "\n - - - - - - SSAKA Console - - - - - -\n";

struct Buttons buttons;

/*  MAIN  */
int main(int argc, char **argv)
{
  GtkApplication *app;
  int status;
  
  g_globals.keychain = (struct schnorr_Keychain *)malloc(sizeof(struct schnorr_Keychain));
  gen_schnorr_keychain(EC_GROUP_new_by_curve_name(NID_secp256k1), g_globals.keychain);
  g_globals.idCounter = 1;

  Y = BN_new();
  BN_dec2bn(&Y, "100");

  g_range = BN_new();
  json_noise = cJSON_CreateObject();
  json_message = cJSON_CreateObject();
  unsigned char *tmp_string = (char *)malloc(sizeof(char) * BUFFER / 2);

  sprintf(tmp_string, "%d", RANGE);
  BN_dec2bn(&g_range, tmp_string);

  gtk_init(&argc, &argv);
  setCSS();
  app = gtk_application_new("vut.ssaka.demo", GTK_WINDOW_TOPLEVEL);
  g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
  status = g_application_run(G_APPLICATION(app), argc, argv);
  g_object_unref(app);

  BN_free(Y);
  free_schnorr_keychain(g_globals.keychain);
  if (setup_toggled == 1)
    free_ssaka_mem();

  return status;
}

/*  APP GUI FUNCTION  */
static void activate(GtkApplication *app, gpointer *user_data)
{
  GtkWidget *window = gtk_application_window_new(app);
  GtkWidget *grid = gtk_grid_new();
  GtkWidget *box_message = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
  GtkWidget *box_add = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
  GtkWidget *box_revoke = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
  GtkWidget *box_devslist = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
  GtkWidget *box_aka = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
  GtkWidget *box_info = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
  GtkWidget *box_keys = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
  GtkWidget *box_precomp = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
  GtkWidget *box_check_precomp = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
  GtkWidget *box_console = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);

  GtkWidget *label_precomp = gtk_label_new("Pre-computation:");
  GtkWidget *noise_check = gtk_check_button_new_with_label("Message");
  GtkWidget *message_check = gtk_check_button_new_with_label("Noise");
  GtkWidget *label_message = gtk_label_new("Message:");
  GtkWidget *spinButton_message = gtk_spin_button_new_with_range(1, 10000, 1);
  GtkWidget *label_add = gtk_label_new("Add:");
  GtkWidget *spinButton_add = gtk_spin_button_new_with_range(1, 7, 1);
  GtkWidget *label_console = gtk_label_new(lg_consoleName);
  GtkWidget *label_device_list = gtk_label_new("Deivces list:");
  GtkWidget *entry_device_list = gtk_entry_new();
  GtkWidget *label_revoke_list = gtk_label_new("Revoke list:");
  GtkWidget *entry_revoke_list = gtk_entry_new();

  buttons.button_keys = gtk_button_new_with_label("Keys");
  buttons.button_params = gtk_button_new_with_label("Parameters");
  buttons.button_setup = gtk_button_new_with_label("Setup");
  buttons.button_akaSeverSignVer = gtk_button_new_with_label("SSAKA Server Sign Verify");
  buttons.button_addShare = gtk_button_new_with_label("SSAKA Add Share");
  buttons.button_revShare = gtk_button_new_with_label("SSAKA Rev Share");

  setButtons(FALSE);

  /*  WINDOW Setup  */
  gtk_window_set_title(GTK_WINDOW(window), "SSAKA Demonstartor");
  gtk_widget_set_name(window, "window");
  gtk_window_set_icon_from_file(window, "./icon.jpg", NULL);
  gtk_container_set_border_width(GTK_CONTAINER(window), 10);
  gtk_window_set_resizable(window, FALSE);
  gtk_widget_set_name(grid, "grid");
  gtk_container_add(GTK_CONTAINER(window), grid);

  gtk_box_set_homogeneous(GTK_BOX(box_message), TRUE);
  gtk_grid_attach(GTK_GRID(grid), box_message, 0, 0, 2, 1);
  gtk_box_set_homogeneous(GTK_BOX(box_add), TRUE);
  gtk_grid_attach(GTK_GRID(grid), box_add, 0, 1, 2, 1);
  gtk_box_set_homogeneous(GTK_BOX(box_revoke), TRUE);
  gtk_grid_attach(GTK_GRID(grid), box_revoke, 0, 2, 2, 1);
  gtk_box_set_homogeneous(GTK_BOX(box_aka), TRUE);
  gtk_grid_attach(GTK_GRID(grid), box_aka, 0, 3, 2, 1);
  gtk_box_set_homogeneous(GTK_BOX(box_devslist), TRUE);
  gtk_grid_attach(GTK_GRID(grid), box_devslist, 0, 4, 2, 1);
  gtk_box_set_homogeneous(GTK_BOX(box_precomp), TRUE);
  gtk_grid_attach(GTK_GRID(grid), box_precomp, 0, 5, 2, 1);
  gtk_box_set_homogeneous(GTK_BOX(box_check_precomp), TRUE);
  gtk_box_pack_end(GTK_BOX(box_precomp), box_check_precomp, TRUE, TRUE, 2);
  gtk_box_set_homogeneous(GTK_BOX(box_console), TRUE);
  gtk_grid_attach(GTK_GRID(grid), box_console, 0, 7, 2, 1);
  gtk_grid_attach(GTK_GRID(grid), box_info, 0, 8, 2, 1);

  gtk_box_pack_start(GTK_BOX(box_aka), box_keys, TRUE, TRUE, 2);

  /*  MESSAGE Label and Entry Box */
  gtk_box_pack_start(GTK_BOX(box_message), label_message, TRUE, TRUE, 2);
  gtk_widget_set_name(GTK_LABEL(label_message), "label");
  gtk_box_pack_end(GTK_BOX(box_message), spinButton_message, TRUE, TRUE, 2);
  gtk_spin_button_set_value(GTK_SPIN_BUTTON(spinButton_message), (double)100);
  g_signal_connect(GTK_SPIN_BUTTON(spinButton_message), "value-changed", G_CALLBACK(updateSpinButton_message), label_console);
  gtk_widget_set_name(GTK_SPIN_BUTTON(spinButton_message), "spinButton");

  gtk_box_pack_start(GTK_BOX(box_add), label_add, TRUE, TRUE, 2);
  gtk_widget_set_name(GTK_LABEL(label_add), "label");
  gtk_box_pack_end(GTK_BOX(box_add), spinButton_add, TRUE, TRUE, 2);
  gtk_spin_button_set_value(GTK_SPIN_BUTTON(spinButton_add), 1);
  g_signal_connect(GTK_SPIN_BUTTON(spinButton_add), "value-changed", G_CALLBACK(updateSpinButton_add), label_console);
  gtk_widget_set_name(GTK_SPIN_BUTTON(spinButton_add), "spinButton");

  gtk_box_pack_start(GTK_BOX(box_revoke), label_revoke_list, TRUE, TRUE, 2);
  gtk_widget_set_name(GTK_LABEL(label_revoke_list), "label");
  gtk_box_pack_start(GTK_BOX(box_revoke), entry_revoke_list, TRUE, TRUE, 2);
  g_signal_connect(GTK_ENTRY(entry_revoke_list), "activate", G_CALLBACK(updateEntry_revoke), label_console);
  gtk_widget_set_name(GTK_ENTRY(entry_revoke_list), "entry");

  gtk_box_pack_start(GTK_BOX(box_precomp), label_precomp, TRUE, TRUE, 2);
  gtk_widget_set_name(GTK_LABEL(label_precomp), "label");
  gtk_box_pack_start(GTK_BOX(box_check_precomp), noise_check, TRUE, TRUE, 2);
  gtk_widget_set_name(GTK_CHECK_BUTTON(noise_check), "checkButton");
  g_signal_connect(GTK_CHECK_BUTTON(noise_check), "toggled", G_CALLBACK(checkNoise), label_console);
  gtk_box_pack_start(GTK_BOX(box_check_precomp), message_check, TRUE, TRUE, 2);
  gtk_widget_set_name(GTK_CHECK_BUTTON(message_check), "checkButton");
  g_signal_connect(GTK_CHECK_BUTTON(message_check), "toggled", G_CALLBACK(checkMessage), label_console);

  /*  BUTTONS
   *  |------ INFO BUTTONS
   *  |     |--> KEYS Button
   *  |     |--> PARAMETERS Button
   *  |
   *  |------ SSAKA KEYS BUTTONS
   *  |     |--> ADD SHARE Button
   *  |     |--> REV SHARE Button
   *  |
   *  |--> SETUP Button
   *  |--> AKA SERVER SIGN VERIFY Button
   *  |--> SSAKA CLIENT PROOF VERIFY Button
   */
  g_signal_connect(G_OBJECT(buttons.button_keys), "clicked", G_CALLBACK(openKeysDialogue), NULL);
  gtk_widget_set_name(GTK_BUTTON(buttons.button_keys), "button");
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_keys), FALSE);
  gtk_box_pack_start(GTK_BOX(box_info), buttons.button_keys, TRUE, TRUE, 2);

  g_signal_connect(G_OBJECT(buttons.button_params), "clicked", G_CALLBACK(openParamDialogue), NULL);
  gtk_widget_set_name(GTK_BUTTON(buttons.button_params), "button");
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_params), FALSE);
  gtk_box_pack_end(GTK_BOX(box_info), buttons.button_params, TRUE, TRUE, 2);

  g_signal_connect(G_OBJECT(buttons.button_addShare), "clicked", G_CALLBACK(ssakaAddShare), GTK_LABEL(label_console));
  gtk_widget_set_name(GTK_BUTTON(buttons.button_addShare), "button");
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_addShare), FALSE);
  gtk_box_pack_end(GTK_BOX(box_keys), buttons.button_addShare, TRUE, TRUE, 2);

  g_signal_connect(G_OBJECT(buttons.button_revShare), "clicked", G_CALLBACK(ssakaRevShare), GTK_LABEL(label_console));
  gtk_widget_set_name(GTK_BUTTON(buttons.button_revShare), "button");
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_revShare), FALSE);
  gtk_box_pack_end(GTK_BOX(box_keys), buttons.button_revShare, TRUE, TRUE, 2);

  g_signal_connect(G_OBJECT(buttons.button_setup), "clicked", G_CALLBACK(akaSetup), GTK_LABEL(label_console));
  gtk_widget_set_name(GTK_BUTTON(buttons.button_setup), "button");
  gtk_box_pack_start(GTK_BOX(box_aka), buttons.button_setup, TRUE, TRUE, 2);

  g_signal_connect(G_OBJECT(buttons.button_akaSeverSignVer), "clicked", G_CALLBACK(akaServerSignVerify), GTK_LABEL(label_console));
  gtk_widget_set_name(GTK_BUTTON(buttons.button_akaSeverSignVer), "button");
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_akaSeverSignVer), FALSE);
  gtk_box_pack_start(GTK_BOX(box_aka), buttons.button_akaSeverSignVer, TRUE, TRUE, 2);

  gtk_box_pack_start(GTK_BOX(box_devslist), label_device_list, TRUE, TRUE, 2);
  gtk_widget_set_name(GTK_LABEL(label_device_list), "label");
  gtk_box_pack_start(GTK_BOX(box_devslist), entry_device_list, TRUE, TRUE, 2);
  g_signal_connect(GTK_ENTRY(entry_device_list), "activate", G_CALLBACK(updateEntry_add), label_console);
  gtk_widget_set_name(GTK_ENTRY(entry_device_list), "entry");

  /*  CONSOLE   */
  gtk_label_set_selectable(GTK_LABEL(label_console), TRUE);
  gtk_label_set_line_wrap_mode(GTK_LABEL(label_console), PANGO_WRAP_CHAR);
  gtk_widget_set_name(GTK_LABEL(label_console), "console");
  gtk_box_pack_start(GTK_BOX(box_console), label_console, TRUE, TRUE, 2);

  gtk_widget_show_all(window);
}

/*  BUTTON FUNCTIONS  */
static void akaSetup(GtkWidget *button, GtkWidget *label)
{
  unsigned int err = ssaka_setup();
  if (err != 1)
  {
    printf(" * SSAKA setup failed!\n");
  }
  setButtons(TRUE);

  setup_toggled = 1;

  gchar *dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Parameters initialized!\n"));
  updateLabel(GTK_LABEL(label), dmp);
}

static void akaServerSignVerify(GtkWidget *button, GtkWidget *label)
{
  struct ServerSign server = *(struct ServerSign *)malloc(sizeof(struct ServerSign));
  init_serversign(g_globals.keychain->ec_group, &server);
  gchar *dmp;

  if (size_used == 0)
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Define used devices first!\n"));
    updateLabel(GTK_LABEL(label), dmp);
    return;
  }

  printf("Y: %s\n", BN_bn2dec(Y));
  unsigned int err = ssaka_akaServerSignVerify(&used_devs, size_used, Y, &server);
  if (err != 1 || BN_is_zero(server.tau_s) == 1)
  {
    // g_strconcat (gtk_label_get_text (console), g_strdup_printf (str));
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 TAU_S = %s\n\tVerification failed! :(\n", BN_bn2dec(server.tau_s)));
  }
  else
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 TAU_S = %s\n\tVerification proceeded! :)\n", BN_bn2dec(server.tau_s)));
  }
  updateLabel(GTK_LABEL(label), dmp);
}

static void ssakaAddShare(GtkWidget *button, GtkWidget *label)
{
  uint err = ssaka_ClientAddShare(add_number);
  gchar *dmp;
  if (err == 1)
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 %lu devices added!\n", add_number));
  }
  else if (err == 2)
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Only %d places left!\n", G_NUMOFDEVICES - currentNumberOfDevices));
  }
  else
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 ERROR! No devices added!\n"));
  }
  updateLabel(GTK_LABEL(label), dmp);
}

static void ssakaRevShare(GtkWidget *button, GtkWidget *label)
{
  uint err = ssaka_ClientRevShare(revoke_devs, size_revoke);
  gchar *dmp;
  if (err == 1)
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 %d devices removed!\n", size_revoke));
    updateLabel(GTK_LABEL(label), dmp);
  }
  else if (err == 2)
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Must remain at least %d devices!\n", G_POLYDEGREE + 1));
    updateLabel(GTK_LABEL(label), dmp);
  }
  else if (err == 3)
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Cannot remove client (0 index)!\n"));
    updateLabel(GTK_LABEL(label), dmp);
  }
  else
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 ERROR! No devices removed!\n"));
    updateLabel(GTK_LABEL(label), dmp);
  }
}

static void openKeysDialogue(GtkWidget *button, gpointer *user_data)
{
  GtkWidget *dialog = gtk_dialog_new();
  BN_CTX *ctx = BN_CTX_secure_new();
  if(!ctx)
  {
    printf(" * Failed to generate CTX!\n");
    return;
  }

  gtk_window_set_title(GTK_WINDOW(dialog), "Generated keys");
  gtk_container_set_border_width(GTK_CONTAINER(dialog), 10);
  gtk_window_set_default_size(GTK_WINDOW(dialog), 500, 500);

  gchar *message = g_strdup_printf(" --- Server --- \nID:\t%u\nPK:\t%s\nSK:\t%s\n\n --- Client --- \nID:\t%u\nPK:\t%s\nSK:\t%s\n\n==================\n\n",
                                   g_serverKeys.ID, EC_POINT_point2hex(g_globals.keychain->ec_group, EC_KEY_get0_public_key(g_serverKeys.keys->keys), POINT_CONVERSION_COMPRESSED, ctx),
                                   BN_bn2hex(EC_KEY_get0_private_key(g_serverKeys.keys->keys)), g_ssaka_devicesKeys[0].ID, BN_bn2hex(g_ssaka_devicesKeys[0].pk),
                                   BN_bn2hex(g_ssaka_devicesKeys[0].sk));
  for (int i = 1; i < currentNumberOfDevices; i++)
  {
    message = g_strconcat(message, g_strdup_printf("--- Device %d ---\nID:\t%u\nPK:\t%s\nSK:\t%s\n\n",
                                                   i, g_ssaka_devicesKeys[i].ID, BN_bn2hex(g_ssaka_devicesKeys[i].pk),
                                                   BN_bn2hex(g_ssaka_devicesKeys[i].sk)));
  }
  message = g_strconcat(message, g_strdup_printf("\nEscape by pressing ESC ..."));

  GtkWidget *label = gtk_label_new(message);
  gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
  gtk_label_set_line_wrap_mode(GTK_LABEL(label), PANGO_WRAP_CHAR);
  gtk_widget_set_size_request(GTK_LABEL(label), 700, 200);
  gtk_widget_set_name(GTK_LABEL(label), "text");
  gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), label, TRUE, TRUE, 0);
  gtk_widget_show(label);

  gtk_widget_show(dialog);

  gtk_widget_set_name(GTK_DIALOG(dialog), "dialog");
  gtk_dialog_run(GTK_DIALOG(dialog));

  gtk_widget_destroy(dialog);
  g_free(message);
  BN_CTX_free(ctx);
}

static void openParamDialogue(GtkWidget *button, gpointer *user_data)
{
  GtkWidget *dialog = gtk_dialog_new();
  BN_CTX *ctx = BN_CTX_secure_new();
  if(!ctx)
  {
    printf(" * Failed to generate CTX!\n");
    return;
  }

  gtk_window_set_title(GTK_WINDOW(dialog), "Parameters");
  gtk_container_set_border_width(GTK_CONTAINER(dialog), 10);
  gtk_window_set_default_size(GTK_WINDOW(dialog), 200, 200);

  gchar *message = g_strdup_printf("\nY:\t%s\n\nQ:\t%s\n\nPK_C:\t%s\n\n\nEscape by pressing ESC ...", BN_bn2dec(Y),
                                   BN_bn2hex(EC_GROUP_get0_order(g_globals.keychain->ec_group)),
                                   EC_POINT_point2hex(g_globals.keychain->ec_group, pk_c, POINT_CONVERSION_COMPRESSED, ctx));

  GtkWidget *label = gtk_label_new(message);
  gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
  gtk_label_set_line_wrap_mode(GTK_LABEL(label), PANGO_WRAP_CHAR);
  gtk_widget_set_size_request(GTK_LABEL(label), 700, 200);
  gtk_widget_set_name(GTK_LABEL(label), "text");
  gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), label, TRUE, TRUE, 0);
  gtk_widget_show(label);

  gtk_widget_show(dialog);

  gtk_widget_set_name(GTK_DIALOG(dialog), "dialog");
  gtk_dialog_run(GTK_DIALOG(dialog));

  gtk_widget_destroy(dialog);
  g_free(message);
  BN_CTX_free(ctx);
}

/*  OTHER FUNCTIONS */
static void updateSpinButton_message(GtkWidget *spinButton, GtkWidget *label)
{
  guint64 int_Y = (guint64)gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spinButton));
  gchar *str_Y = (gchar *)malloc(sizeof(gchar) * BUFFER / 2);
  sprintf(str_Y, "%lu", int_Y);
  BN_dec2bn(&Y, str_Y);
  gchar *dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Message value changed to %lu!\n", int_Y));
  updateLabel(GTK_LABEL(label), dmp);
  free(str_Y);
}

static void updateSpinButton_add(GtkWidget *spinButton, GtkWidget *label)
{
  add_number = (guint64)gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spinButton));
  gchar *dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Add value changed to %lu!\n", add_number));
  updateLabel(GTK_LABEL(label), dmp);
}

void updateLabel(GtkLabel *label, gchar *string)
{
  gtk_label_set_text(GTK_LABEL(label), g_locale_to_utf8(string, -1, NULL, NULL, NULL));
  g_free(string);
}

void updateEntry_add(GtkWidget *entry, GtkWidget *label)
{
  gchar *text = gtk_entry_get_text(entry);
  gint counter = 0;
  gchar *dmp;
  for (int i = 0; i < strlen(text); i++)
  {
    if (text[i] >= '0' && text[i] <= '9')
    {
      used_devs[counter++] = text[i] - '0';
    }
  }
  if (counter >= currentNumberOfDevices)
  {
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Can be used only %d devices!\n", currentNumberOfDevices - 1));
    updateLabel(GTK_LABEL(label), dmp);
  }
  else
  {
    size_used = counter;
    dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Number of used devices is %d!\n", counter));
    updateLabel(GTK_LABEL(label), dmp);

    printf("ADD: [");
    for (int j = 0; j < counter; j++)
    {
      printf(" %d ", used_devs[j]);
    }
    printf("]\n");
  }
}

void updateEntry_revoke(GtkWidget *entry, GtkWidget *label)
{
  gchar *text = gtk_entry_get_text(entry);
  gint counter = 0;
  for (int i = 0; i < strlen(text); i++)
  {
    if (text[i] >= '0' && text[i] <= '9')
    {
      revoke_devs[counter++] = text[i] - '0';
    }
  }
  size_revoke = counter;
  gchar *dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Number of revoked devices is %d!\n", counter));
  updateLabel(GTK_LABEL(label), dmp);

  printf("REVOKE: [");
  for (int j = 0; j < counter; j++)
  {
    printf(" %d ", revoke_devs[j]);
  }
  printf("]\n");
}

void checkNoise(GtkWidget *entry, GtkWidget *label)
{
  if (pre_message)
    pre_message = 0;
  else
    pre_message = 1;

  printf("Message pre-computation %s!\n", (pre_message)? "On":"Off");
  gchar *dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Message pre-computation %s!\n", (pre_message)? "On":"Off"));
  updateLabel(GTK_LABEL(label), dmp);
}

void checkMessage(GtkWidget *entry, GtkWidget *label)
{
  if (pre_noise)
    pre_noise = 0;
  else
    pre_noise = 1;

  printf("Noise pre-computation %s!\n", (pre_noise)? "On":"Off");
  gchar *dmp = g_strconcat(lg_consoleName, g_strdup_printf("\n\x20>\x20 Noise pre-computation %s!\n", (pre_noise)? "On":"Off"));
  updateLabel(GTK_LABEL(label), dmp);
}

void setButtons(gboolean enabled)
{
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_akaSeverSignVer), enabled);
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_keys), enabled);
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_params), enabled);
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_addShare), enabled);
  gtk_widget_set_sensitive(GTK_BUTTON(buttons.button_revShare), enabled);
}

void setCSS()
{
  GtkCssProvider *provider;
  GdkDisplay *display;
  GdkScreen *screen;

  provider = gtk_css_provider_new();
  display = gdk_display_get_default();
  screen = gdk_display_get_default_screen(display);
  gtk_style_context_add_provider_for_screen(screen, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

  const gchar *cssFile = "style.css";
  GError *error = 0;

  gtk_css_provider_load_from_file(provider, g_file_new_for_path(cssFile), &error);
  g_object_unref(provider);
}
