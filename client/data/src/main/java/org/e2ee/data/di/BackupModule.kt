package org.e2ee.data.di

import android.content.Context
import android.content.SharedPreferences
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import org.e2ee.data.local.user.share.RecoveryShareStore
import org.e2ee.data.remote.shares.RemoteShareRepository
import org.e2ee.data.repository.backup.BackupExporter
import org.e2ee.data.repository.backup.BackupPreferencesRepository
import org.e2ee.data.repository.backup.BackupRepository
import org.e2ee.data.repository.backup.DriveTokenManager
import org.e2ee.data.repository.backup.GoogleBackupAuthRepository
import org.e2ee.data.repository.backup.GoogleDriveRepository
import org.e2ee.domain.repository.BackupAuthRepository
import org.e2ee.domain.usecase.EnableDriveBackupUseCase
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object BackupModule {

    @Provides
    @Singleton
    fun provideBackupPreferencesRepository(prefs: SharedPreferences): BackupPreferencesRepository {
        return BackupPreferencesRepository(prefs)
    }

    @Provides
    @Singleton
    fun provideDriveTokenManager(prefs: SharedPreferences): DriveTokenManager {
        return DriveTokenManager(prefs)
    }

    @Provides
    @Singleton
    fun provideGoogleBackupAuthRepository(
        @ApplicationContext context: Context
    ): GoogleBackupAuthRepository {
        val webClientId = "921118326524-rogl7gi2bqo3og6gj450l33socqb1tnj.apps.googleusercontent.com"
        return GoogleBackupAuthRepository(webClientId)
    }

    @Provides
    @Singleton
    fun provideBackupAuthRepository(
        googleBackupAuthRepository: GoogleBackupAuthRepository
    ): BackupAuthRepository = googleBackupAuthRepository

    @Provides
    @Singleton
    fun provideEnableDriveBackupUseCase(
        backupAuthRepository: BackupAuthRepository
    ): EnableDriveBackupUseCase = EnableDriveBackupUseCase(backupAuthRepository)

    @Provides
    @Singleton
    fun provideBackupRepository(
        backupExporter: BackupExporter,
        driveRepository: GoogleDriveRepository,
        recoveryShareStore: RecoveryShareStore,
        remoteShareRepository: RemoteShareRepository
    ): BackupRepository = BackupRepository(
        backupExporter = backupExporter,
        driveRepository = driveRepository,
        recoveryShareStore = recoveryShareStore,
        remoteShareRepository = remoteShareRepository
    )
}