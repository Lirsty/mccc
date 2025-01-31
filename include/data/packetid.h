#ifndef _PACKETID_H
#define _PACKETID_H

#define PROTOCOL_VERSION 767

#define handshaking_serverbound_handshake 0x00
#define handshaking_serverbound_legacy_server_list_ping 0xFE


#define status_clientbound_status_response 0x00
#define status_clientbound_ping_response 0x01


#define status_serverbound_status_request 0x00
#define status_serverbound_ping_request 0x01


#define login_clientbound_disconnect 0x00
#define login_clientbound_encryption_request 0x01
#define login_clientbound_login_success 0x02
#define login_clientbound_set_compression 0x03
#define login_clientbound_login_plugin_request 0x04
#define login_clientbound_cookie_request 0x05


#define login_serverbound_login_start 0x00
#define login_serverbound_encryption_response 0x01
#define login_serverbound_login_plugin_response 0x02
#define login_serverbound_login_acknowledged 0x03
#define login_serverbound_cookie_response 0x04


#define configuration_clientbound_cookie_request 0x00
#define configuration_clientbound_plugin_message 0x01
#define configuration_clientbound_disconnect 0x02
#define configuration_clientbound_finish_configuration 0x03
#define configuration_clientbound_keep_alive 0x04
#define configuration_clientbound_ping 0x05
#define configuration_clientbound_reset_chat 0x06
#define configuration_clientbound_registry_data 0x07
#define configuration_clientbound_remove_resource_pack 0x08
#define configuration_clientbound_add_resource_pack 0x09
#define configuration_clientbound_store_cookie 0x0A
#define configuration_clientbound_transfer 0x0B
#define configuration_clientbound_feature_flags 0x0C
#define configuration_clientbound_update_tags 0x0D
#define configuration_clientbound_known_packs 0x0E
#define configuration_clientbound_custom_report_details 0x0F
#define configuration_clientbound_server_links 0x10
// play_clientbound ?
// #define configuration_clientbound_custom_report_details 0x7A
// #define configuration_clientbound_server_links 0x7B


#define configuration_serverbound_client_information 0x00
#define configuration_serverbound_cookie_response 0x01
#define configuration_serverbound_plugin_message 0x02
#define configuration_serverbound_acknowledge_finish_configuration 0x03
#define configuration_serverbound_keep_alive 0x04
#define configuration_serverbound_pong 0x05
#define configuration_serverbound_resource_pack_response 0x06
#define configuration_serverbound_known_packs 0x07


#define play_clientbound_bundle_delimiter 0x00
#define play_clientbound_spawn_entity 0x01
#define play_clientbound_spawn_experience_orb 0x02
#define play_clientbound_entity_animation 0x03
#define play_clientbound_award_statistics 0x04
#define play_clientbound_acknowledge_block_change 0x05
#define play_clientbound_set_block_destroy_stage 0x06
#define play_clientbound_block_entity_data 0x07
#define play_clientbound_block_action 0x08
#define play_clientbound_block_update 0x09
#define play_clientbound_boss_bar 0x0A
#define play_clientbound_change_difficulty 0x0B
#define play_clientbound_chunk_batch_finished 0x0C
#define play_clientbound_chunk_batch_start 0x0D
#define play_clientbound_chunk_biomes 0x0E
#define play_clientbound_clear_titles 0x0F
#define play_clientbound_command_suggestions_response 0x10
#define play_clientbound_commands 0x11
#define play_clientbound_close_container 0x12
#define play_clientbound_set_container_content 0x13
#define play_clientbound_set_container_property 0x14
#define play_clientbound_set_container_slot 0x15
#define play_clientbound_cookie_request 0x16
#define play_clientbound_set_cooldown 0x17
#define play_clientbound_chat_suggestions 0x18
#define play_clientbound_clientbound_plugin_message 0x19
#define play_clientbound_damage_event 0x1A
#define play_clientbound_debug_sample 0x1B
#define play_clientbound_delete_message 0x1C
#define play_clientbound_disconnect 0x1D
#define play_clientbound_disguised_chat_message 0x1E
#define play_clientbound_entity_event 0x1F
#define play_clientbound_explosion 0x20
#define play_clientbound_unload_chunk 0x21
#define play_clientbound_game_event 0x22
#define play_clientbound_open_horse_screen 0x23
#define play_clientbound_hurt_animation 0x24
#define play_clientbound_initialize_world_border 0x25
#define play_clientbound_keep_alive 0x26
#define play_clientbound_chunk_data_and_update_light 0x27
#define play_clientbound_world_event 0x28
#define play_clientbound_particle 0x29
#define play_clientbound_update_light 0x2A
#define play_clientbound_login 0x2B
#define play_clientbound_map_data 0x2C
#define play_clientbound_merchant_offers 0x2D
#define play_clientbound_update_entity_position 0x2E
#define play_clientbound_update_entity_position_and_rotation 0x2F
#define play_clientbound_update_entity_rotation 0x30
#define play_clientbound_move_vehicle 0x31
#define play_clientbound_open_book 0x32
#define play_clientbound_open_screen 0x33
#define play_clientbound_open_sign_editor 0x34
#define play_clientbound_ping 0x35
#define play_clientbound_ping_response 0x36
#define play_clientbound_place_ghost_recipe 0x37
#define play_clientbound_player_abilities 0x38
#define play_clientbound_player_chat_message 0x39
#define play_clientbound_end_combat 0x3A
#define play_clientbound_enter_combat 0x3B
#define play_clientbound_combat_death 0x3C
#define play_clientbound_player_info_remove 0x3D
#define play_clientbound_player_info_update 0x3E
#define play_clientbound_look_at 0x3F
#define play_clientbound_synchronize_player_position 0x40
#define play_clientbound_update_recipe_book 0x41
#define play_clientbound_remove_entities 0x42
#define play_clientbound_remove_entity_effect 0x43
#define play_clientbound_reset_score 0x44
#define play_clientbound_remove_resource_pack 0x45
#define play_clientbound_add_resource_pack 0x46
#define play_clientbound_respawn 0x47
#define play_clientbound_set_head_rotation 0x48
#define play_clientbound_update_section_blocks 0x49
#define play_clientbound_select_advancements_tab 0x4A
#define play_clientbound_server_data 0x4B
#define play_clientbound_set_action_bar_text 0x4C
#define play_clientbound_set_border_center 0x4D
#define play_clientbound_set_border_lerp_size 0x4E
#define play_clientbound_set_border_size 0x4F
#define play_clientbound_set_border_warning_delay 0x50
#define play_clientbound_set_border_warning_distance 0x51
#define play_clientbound_set_camera 0x52
#define play_clientbound_set_held_item 0x53
#define play_clientbound_set_center_chunk 0x54
#define play_clientbound_set_render_distance 0x55
#define play_clientbound_set_default_spawn_position 0x56
#define play_clientbound_display_objective 0x57
#define play_clientbound_set_entity_metadata 0x58
#define play_clientbound_link_entities 0x59
#define play_clientbound_set_entity_velocity 0x5A
#define play_clientbound_set_equipment 0x5B
#define play_clientbound_set_experience 0x5C
#define play_clientbound_set_health 0x5D
#define play_clientbound_update_objectives 0x5E
#define play_clientbound_set_passengers 0x5F
#define play_clientbound_update_teams 0x60
#define play_clientbound_update_score 0x61
#define play_clientbound_set_simulation_distance 0x62
#define play_clientbound_set_subtitle_text 0x63
#define play_clientbound_update_time 0x64
#define play_clientbound_set_title_text 0x65
#define play_clientbound_set_title_animation_times 0x66
#define play_clientbound_entity_sound_effect 0x67
#define play_clientbound_sound_effect 0x68
#define play_clientbound_start_configuration 0x69
#define play_clientbound_stop_sound 0x6A
#define play_clientbound_store_cookie 0x6B
#define play_clientbound_system_chat_message 0x6C
#define play_clientbound_set_tab_list_header_and_footer 0x6D
#define play_clientbound_tag_query_response 0x6E
#define play_clientbound_pickup_item 0x6F
#define play_clientbound_teleport_entity 0x70
#define play_clientbound_set_ticking_state 0x71
#define play_clientbound_step_tick 0x72
#define play_clientbound_transfer 0x73
#define play_clientbound_update_advancements 0x74
#define play_clientbound_update_attributes 0x75
#define play_clientbound_entity_effect 0x76
#define play_clientbound_update_recipes 0x77
#define play_clientbound_update_tags 0x78
#define play_clientbound_projectile_power 0x79


#define play_serverbound_confirm_teleportation 0x00
#define play_serverbound_query_block_entity_tag 0x01
#define play_serverbound_change_difficulty 0x02
#define play_serverbound_acknowledge_message 0x03
#define play_serverbound_chat_command 0x04
#define play_serverbound_signed_chat_command 0x05
#define play_serverbound_chat_message 0x06
#define play_serverbound_player_session 0x07
#define play_serverbound_chunk_batch_received 0x08
#define play_serverbound_client_status 0x09
#define play_serverbound_client_information 0x0A
#define play_serverbound_command_suggestions_request 0x0B
#define play_serverbound_acknowledge_configuration 0x0C
#define play_serverbound_click_container_button 0x0D
#define play_serverbound_click_container 0x0E
#define play_serverbound_close_container 0x0F
#define play_serverbound_change_container_slot_state 0x10
#define play_serverbound_cookie_response 0x11
#define play_serverbound_plugin_message 0x12
#define play_serverbound_debug_sample_subscription 0x13
#define play_serverbound_edit_book 0x14
#define play_serverbound_query_entity_tag 0x15
#define play_serverbound_interact 0x16
#define play_serverbound_jigsaw_generate 0x17
#define play_serverbound_keep_alive 0x18
#define play_serverbound_lock_difficulty 0x19
#define play_serverbound_set_player_position 0x1A
#define play_serverbound_set_player_position_and_rotation 0x1B
#define play_serverbound_set_player_rotation 0x1C
#define play_serverbound_set_player_on_ground 0x1D
#define play_serverbound_move_vehicle 0x1E
#define play_serverbound_paddle_boat 0x1F
#define play_serverbound_pick_item 0x20
#define play_serverbound_ping_request 0x21
#define play_serverbound_place_recipe 0x22
#define play_serverbound_player_abilities 0x23
#define play_serverbound_player_action 0x24
#define play_serverbound_player_command 0x25
#define play_serverbound_player_input 0x26
#define play_serverbound_pong 0x27
#define play_serverbound_change_recipe_book_settings 0x28
#define play_serverbound_set_seen_recipe 0x29
#define play_serverbound_rename_item 0x2A
#define play_serverbound_resource_pack_response 0x2B
#define play_serverbound_seen_advancements 0x2C
#define play_serverbound_select_trade 0x2D
#define play_serverbound_set_beacon_effect 0x2E
#define play_serverbound_set_held_item 0x2F
#define play_serverbound_program_command_block 0x30
#define play_serverbound_program_command_block_minecart 0x31
#define play_serverbound_set_creative_mode_slot 0x32
#define play_serverbound_program_jigsaw_block 0x33
#define play_serverbound_program_structure_block 0x34
#define play_serverbound_update_sign 0x35
#define play_serverbound_swing_arm 0x36
#define play_serverbound_teleport_to_entity 0x37
#define play_serverbound_use_item_on 0x38
#define play_serverbound_use_item 0x39


#endif /* _PACKETID_H */