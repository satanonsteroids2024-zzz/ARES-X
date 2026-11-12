"""ARES-X action modules — domain-split facade.

The former 3,569-line ``actions.py`` god file was split into domain
modules (desktop, info, file_ops, system, office, web, dev, content,
assistant). Every public name remains importable from this package
and from ``aresx.modules.actions`` for backward compatibility.
"""

from aresx.modules.actions._helpers import _ps_run, _safe_pyauto, _sanitize
from aresx.modules.actions.desktop import open_app, close_window, minimize_all, switch_window, lock_screen, search_web, price_compare, volume, brightness, take_screenshot, read_screen, summarize_screen, summarize_youtube, type_text, press_keys
from aresx.modules.actions.info import take_note, recall_memory, show_notes, calculator, weather, currency_convert, time_in, wikipedia, define_word, set_timer
from aresx.modules.actions.file_ops import whatsapp_send, send_email, find_file, open_folder, clipboard_read, clipboard_set, system_info, battery_status, shutdown, restart, sleep_pc, git_status, git_auto_commit, git_push, strip_exif, strip_exif_folder, fix_clipboard_code
from aresx.modules.actions.system import manage_api_keys, window_manager, app_launcher, file_batch_ops, system_cleanup, network_config, task_scheduler, performance_monitor, set_wallpaper, schedule_sleep
from aresx.modules.actions.office import excel_automate, word_automate, pptx_automate, email_draft_schedule, calendar_ops, slack_ops, pdf_manipulate, invoice_generate
from aresx.modules.actions.web import browser_tabs, web_scrape, price_monitor, form_autofill, screenshot_to_markdown
from aresx.modules.actions.dev import git_advanced, docker_ops, db_query, api_request, log_tail, run_tests, package_update, generate_unit_tests
from aresx.modules.actions.content import fact_check, research_aggregator, email_summarizer, meeting_notes_parser, financial_data, podcast_transcribe, image_generate, social_media_post, meme_generator, analytics_report, qr_code_generate, link_shortener
from aresx.modules.actions.assistant import macro_ops, multilingual_detect, voice_confidence_check, set_voice_macro_trigger, discord_bot_ops, home_assistant_ops, vscode_ops, competitor_tracker

__all__ = ['open_app', 'close_window', 'minimize_all', 'switch_window', 'lock_screen', 'search_web', 'price_compare', 'volume', 'brightness', 'take_screenshot', 'read_screen', 'summarize_screen', 'summarize_youtube', 'type_text', 'press_keys', 'take_note', 'recall_memory', 'show_notes', 'calculator', 'weather', 'currency_convert', 'time_in', 'wikipedia', 'define_word', 'set_timer', 'whatsapp_send', 'send_email', 'find_file', 'open_folder', 'clipboard_read', 'clipboard_set', 'system_info', 'battery_status', 'shutdown', 'restart', 'sleep_pc', 'git_status', 'git_auto_commit', 'git_push', 'strip_exif', 'strip_exif_folder', 'fix_clipboard_code', 'manage_api_keys', 'window_manager', 'app_launcher', 'file_batch_ops', 'system_cleanup', 'network_config', 'task_scheduler', 'performance_monitor', 'set_wallpaper', 'schedule_sleep', 'excel_automate', 'word_automate', 'pptx_automate', 'email_draft_schedule', 'calendar_ops', 'slack_ops', 'pdf_manipulate', 'invoice_generate', 'browser_tabs', 'web_scrape', 'price_monitor', 'form_autofill', 'screenshot_to_markdown', 'git_advanced', 'docker_ops', 'db_query', 'api_request', 'log_tail', 'run_tests', 'package_update', 'generate_unit_tests', 'fact_check', 'research_aggregator', 'email_summarizer', 'meeting_notes_parser', 'financial_data', 'podcast_transcribe', 'image_generate', 'social_media_post', 'meme_generator', 'analytics_report', 'qr_code_generate', 'link_shortener', 'macro_ops', 'multilingual_detect', 'voice_confidence_check', 'set_voice_macro_trigger', 'discord_bot_ops', 'home_assistant_ops', 'vscode_ops', 'competitor_tracker']
