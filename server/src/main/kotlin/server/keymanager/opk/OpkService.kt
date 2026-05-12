package server.keymanager.opk

import org.springframework.stereotype.Service
import server.keymanager.dto.UpdateOpkKeys
import kotlin.collections.component1
import kotlin.collections.component2

@Service
class OpkService(
    private val opkRepository: OneTimePreKeysRepository
) {

    fun updateOpkKeys(updateOpkKeys: UpdateOpkKeys){
        updateOpkKeys.opkMap.forEach { (keyId, keyValue) ->
            val oneTimePreKey = OneTimePreKeys(
                userId = updateOpkKeys.userId,
                keyId = keyId,
                key = keyValue
            )
            opkRepository.save(oneTimePreKey)
        }
    }
}