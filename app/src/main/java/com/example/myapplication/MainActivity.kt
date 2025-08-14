package com.example.myapplication

import android.os.Bundle
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    private val client = HttpClient(CIO)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        val textView: TextView = findViewById(R.id.textViewResult)

        // 🔄 Gọi HTTP GET và cập nhật TextView
        lifecycleScope.launch {
            val result = fetchData()
            textView.text = result
        }
    }

    private suspend fun fetchData(): String {
        return try {
            val response: HttpResponse = client.get("http://14.187.168.7:3000/ping")
            response.bodyAsText()
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        client.close()
    }
}
