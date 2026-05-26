package org.e2ee.client.ui.elements

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import org.e2ee.client.R

@Composable
fun MessageCard(
    modifier: Modifier = Modifier,
    otherUserName: String,
    lastMessage: String,
    timestamp: String,
    unreadMessageCount: Int,
    onClick: () -> Unit = {}
) {
    Row(
        modifier = modifier
            .clickable {
                onClick()
            }
            .padding(vertical = 8.dp)
    ) {
        Image(
            painter = painterResource(R.drawable.outline_person_24),
            contentDescription = "Contact profile picture",
            modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
        )

        Spacer(modifier = Modifier.size(8.dp))

        Column {
            Text(text = otherUserName)

            Spacer(modifier = Modifier.height(4.dp))

            Text(text = lastMessage)
        }

        Spacer(modifier = Modifier.weight(1f))

        Column {
            Text(text = timestamp)

            if (unreadMessageCount > 0) {
                Text(text = unreadMessageCount.toString())
            }
        }
    }
}