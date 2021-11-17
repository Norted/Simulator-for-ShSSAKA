#include <gtk/gtk.h>
#include <SSAKA.h>

unsigned int Y = 100;

static void activate (GtkApplication *app, gpointer user_data);
void updateLabel( GtkLabel *console, gchar *string);
static void aka_setup (GtkWidget *widget, gpointer data);
static void aka_server_sign_verify (GtkWidget *widget, GtkLabel *console);

/*  MAIN  */

int main (int argc, char **argv)
{
  GtkApplication *app;
  int status;

  gtk_init (&argc,&argv);
  
  app = gtk_application_new ("vut.ssaka.demo", GTK_WINDOW_TOPLEVEL);
  g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
  status = g_application_run (G_APPLICATION (app), argc, argv);
  g_object_unref (app);

  return status;
}

/*  APP GUI FUNCTION  */

static void activate (GtkApplication *app, gpointer user_data) {
  
  GtkWidget *window = gtk_application_window_new (app);
  GtkWidget *grid = gtk_grid_new ();

  GtkWidget *console = gtk_label_new ("-- SSAKA Demonstartor --\n");
  
  GtkWidget *setupButton = gtk_button_new_with_label ("Setup");
  GtkWidget *akaSeverSignVerButton = gtk_button_new_with_label ("AKA Server Sign Verify");

  gtk_window_set_title (GTK_WINDOW (window), "Window");
  gtk_container_set_border_width (GTK_CONTAINER (window), 10);
  gtk_container_add (GTK_CONTAINER (window), grid);
  g_signal_connect (GTK_WINDOW (window), "destroy", G_CALLBACK(gtk_main_quit), NULL);

  gtk_label_set_selectable (GTK_LABEL(console), TRUE);
  gtk_grid_attach (GTK_GRID (grid), console, 0, 4, 2, 4);

  g_signal_connect (G_OBJECT (setupButton), "clicked", G_CALLBACK (aka_setup), console);
  gtk_grid_attach (GTK_GRID (grid), setupButton, 0, 0, 1, 1);

  g_signal_connect (G_OBJECT (akaSeverSignVerButton), "clicked", G_CALLBACK (aka_server_sign_verify), console);
  gtk_grid_attach (GTK_GRID (grid), akaSeverSignVerButton, 1, 0, 1, 1);
  
  gtk_widget_show_all (window);
  gtk_main();
}

/*  OTHER FUNCTIONS */

void updateLabel( GtkLabel *console, gchar *string) {
  string = g_locale_to_utf8(string, -1, NULL, NULL, NULL);
  gtk_label_set_text (GTK_LABEL (console), string);
  g_free (string);
}

static void aka_setup (GtkWidget *widget, gpointer data) {
  setup();
}

static void aka_server_sign_verify (GtkWidget *widget, GtkLabel *console) {
  struct ServerSign server = aka_serverSignVerify(Y, g_serverKeys.sk, g_clientKeys.pk);
  if (server.tau_s == 0) {
    gchar *dmp = g_strconcat (gtk_label_get_text (console), g_strdup_printf ("\nTAU_S = %d\nVerification failed! :(\nProtocol ends.\n", server.tau_s));
    updateLabel (GTK_LABEL (console), dmp);
  }
  else {
    gchar *dmp = g_strconcat (gtk_label_get_text (console), g_strdup_printf ("\nTAU_S = %d\nVerification proceeded! :)\nProtocol continues.\n", server.tau_s));
    updateLabel (GTK_LABEL (console), dmp);
  }
}


/*
https://github.com/steshaw/gtk-examples/blob/master/ch04.button.edit.combo/button.c
https://docs.gtk.org/gtk4/signal.Button.clicked.html
*/
